import base64
import json
import time
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from threading import Event
from unittest.mock import Mock, patch

from TwitchChannelPointsMiner.classes.RewardAutomation import (
    RewardAutomation,
    RewardAutomationSettings,
)
from TwitchChannelPointsMiner.classes.Settings import Priority
from TwitchChannelPointsMiner.classes.Twitch import Twitch
from TwitchChannelPointsMiner.classes.entities.Rewards import (
    Replay,
    StreakRecovery,
    WeeklyRewards,
)
from TwitchChannelPointsMiner.classes.entities.Streamer import (
    Streamer,
    StreamerSettings,
)


def weekly():
    return WeeklyRewards("event", time.time() + 3600, 0, 0, 3, False, False)


def recovery():
    return StreakRecovery(3, frozenset({"missed"}), time.time() + 3600)


def response(field, data):
    return {"data": {"channel": {"self": {field: data}}}}


def milestone(*, days=3, missed=True):
    return {
        "watchStreakMilestone": {"value": days},
        "missedStreams": (
            [{"broadcastIdentifiers": [{"id": "missed"}]}] if missed else []
        ),
        "expiresAt": (
            datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()
            if missed
            else None
        ),
    }


def weekly_data(*, visited=False):
    return {
        "eventConfig": {
            "id": "event",
            "endDate": datetime.fromtimestamp(
                time.time() + 3600, timezone.utc
            ).isoformat(),
            "rewardTiers": [{"tier": 1}, {"tier": 2}, {"tier": 3}],
        },
        "daysVisitedThisWeek": int(visited),
        "accumulatedWeeks": 0,
        "hasVisitedToday": visited,
        "hasEarnedWeeklyRewardThisWeek": False,
    }


class EligibilityTest(unittest.TestCase):
    def test_weekly_response_validation(self):
        data = weekly_data()
        self.assertTrue(WeeklyRewards.from_dict(data).needs_visit())
        for field, value in (
            ("daysVisitedThisWeek", True),
            ("hasVisitedToday", "false"),
            ("eventConfig", None),
        ):
            self.assertIsNone(WeeklyRewards.from_dict({**data, field: value}))

    def test_weekly_eligibility_and_expiry(self):
        state = weekly()
        self.assertTrue(state.needs_visit())
        for invalid in (
            replace(state, ends_at=time.time() - 1),
            replace(state, visited_today=True),
            replace(state, earned_this_week=True),
            replace(state, accumulated_weeks=3),
            replace(state, reward_count=0),
        ):
            with self.subTest(state=invalid):
                self.assertFalse(invalid.needs_visit())

    def test_weekly_confirmation_requires_same_active_event(self):
        state = weekly()
        self.assertTrue(replace(state, visited_today=True).progressed_from(state))
        self.assertFalse(state.progressed_from(state))
        self.assertFalse(
            replace(state, event_id="new", visited_today=True).progressed_from(state)
        )
        self.assertFalse(
            replace(state, visited_today=True).progressed_from(state, now=state.ends_at)
        )

    def test_recovery_requires_three_days_missed_broadcast_and_future_window(self):
        state = recovery()
        self.assertTrue(state.recoverable())
        for invalid in (
            replace(state, streak_days=2),
            replace(state, missed_broadcasts=frozenset()),
            replace(state, expires_at=None),
            replace(state, expires_at=time.time() - 1),
        ):
            self.assertFalse(invalid.recoverable())

    def test_recovery_confirmation_rejects_reset_or_expired_window(self):
        state = recovery()
        restored = replace(state, missed_broadcasts=frozenset(), expires_at=None)
        self.assertTrue(restored.recovered_from(state))
        self.assertFalse(replace(restored, streak_days=0).recovered_from(state))
        self.assertFalse(restored.recovered_from(state, now=state.expires_at))

    def test_missing_or_malformed_recovery_fields_cannot_confirm_success(self):
        data = milestone(missed=False)
        self.assertIsNotNone(StreakRecovery.from_dict(data))
        for key in ("missedStreams", "expiresAt", "watchStreakMilestone"):
            invalid = data.copy()
            invalid.pop(key)
            self.assertIsNone(StreakRecovery.from_dict(invalid))
        self.assertIsNone(StreakRecovery.from_dict(milestone(days=True)))

    def test_replay_filters_invalid_durations_and_identifiers(self):
        clip = {
            "id": "clip",
            "slug": "slug",
            "url": "https://clips.twitch.tv/slug",
            "durationSeconds": 5,
        }
        self.assertIsNotNone(Replay.from_dict(clip, "clip"))
        for duration in (4, None, True, float("nan"), float("inf")):
            self.assertIsNone(
                Replay.from_dict({**clip, "durationSeconds": duration}, "clip")
            )
        self.assertIsNone(Replay.from_dict({**clip, "slug": ""}, "clip"))
        self.assertIsNone(Replay.from_dict({"id": "bad", "lengthSeconds": 360}, "vod"))
        self.assertIsNone(Replay.from_dict({"id": "123", "lengthSeconds": 299}, "vod"))

    def test_settings_reject_unbounded_or_invalid_intervals(self):
        for value in (0, -1, float("inf"), float("nan"), True, "30"):
            with self.assertRaises(ValueError):
                RewardAutomationSettings(max_clip_watch_seconds=value)


class RewardAutomationTest(unittest.TestCase):
    def setUp(self):
        settings = StreamerSettings()
        settings.default()
        self.streamer = Streamer("channel", settings)
        self.streamer.channel_id = "123"
        self.streamer.stream.spade_url = "https://spade.example.test/"
        self.twitch = Mock(running=True, user_agent="ua")
        self.twitch.twitch_login.get_user_id.return_value = "456"
        self.twitch._streamer_has_reached_points_limit.return_value = False
        self.twitch._request_with_retry.return_value = Mock(status_code=204)
        self.worker = RewardAutomation(self.twitch, [self.streamer])
        self.clip = Replay(
            "clip", "clip", "missed", 5, "https://clips.twitch.tv/slug", "slug"
        )
        self.vod = Replay("vod", "999", "missed", 360)

    def virtual_play(self, operation):
        clock = [0.0]

        def wait(seconds):
            clock[0] += seconds
            return self.worker._active()

        with (
            patch(
                "TwitchChannelPointsMiner.classes.RewardAutomation.time.monotonic",
                side_effect=lambda: clock[0],
            ),
            patch.object(self.worker, "_wait", side_effect=wait),
        ):
            return operation()

    def test_api_errors_preserve_cached_state_but_cannot_confirm(self):
        self.streamer.weekly_rewards = weekly()
        self.twitch.post_gql_request.return_value = {
            "errors": [{"message": "service timeout"}]
        }
        self.assertIsNone(self.worker.refresh_weekly_rewards(self.streamer))
        self.assertIsNotNone(self.streamer.weekly_rewards)
        self.assertFalse(
            self.worker._confirmed(
                self.streamer, "weekly", self.streamer.weekly_rewards
            )
        )
        self.twitch.post_gql_request.return_value = response("weeklyVisitRewards", None)
        self.worker.refresh_weekly_rewards(self.streamer)
        self.assertIsNone(self.streamer.weekly_rewards)

    def test_malformed_response_preserves_state_without_confirmation(self):
        self.streamer.streak_recovery = recovery()
        for result in (
            {},
            response("watchStreakMilestone", {"watchStreakMilestone": {"value": 3}}),
            None,
        ):
            self.twitch.post_gql_request.return_value = result
            self.assertIsNone(self.worker.refresh_streak_recovery(self.streamer))
            self.assertIsNotNone(self.streamer.streak_recovery)

    def test_known_weekly_final_tier_error_disables_work(self):
        self.streamer.weekly_rewards = weekly()
        self.twitch.post_gql_request.return_value = {
            "errors": [
                {
                    "message": 'graphql: got nil for non-null "WeeklyVisitRewardTier"',
                    "path": ["channel", "self", "weeklyVisitRewards", "currentReward"],
                }
            ]
        }
        self.worker.refresh_weekly_rewards(self.streamer)
        self.assertIsNone(self.streamer.weekly_rewards)
        self.twitch._log_gql_errors.assert_not_called()

    def test_recovery_clip_works_without_weekly_reward(self):
        self.streamer.streak_recovery = recovery()
        self.twitch.post_gql_request.return_value = response(
            "watchStreakMilestone", milestone(missed=False)
        )
        self.assertTrue(
            self.virtual_play(
                lambda: self.worker._watch_clip(
                    self.streamer, "recovery", recovery(), self.clip
                )
            )
        )
        events = [
            json.loads(base64.b64decode(call.kwargs["data"]["data"]))[0]
            for call in self.twitch._request_with_retry.call_args_list
        ]
        self.assertEqual(
            [event["event"] for event in events], ["video-play", "n_second_play"]
        )
        self.assertEqual(events[1]["properties"]["seconds_after_play"], 5)
        self.assertEqual(
            events[0]["properties"]["play_session_id"],
            events[1]["properties"]["play_session_id"],
        )

    def test_weekly_clip_requires_confirmed_visit_and_refreshes_balance(self):
        baseline = self.worker.refresh_weekly_rewards(self.streamer)
        self.assertIsNone(baseline)
        self.twitch.post_gql_request.return_value = response(
            "weeklyVisitRewards", weekly_data()
        )
        baseline = self.worker.refresh_weekly_rewards(self.streamer)
        self.assertIsNotNone(baseline)
        self.twitch.post_gql_request.return_value = response(
            "weeklyVisitRewards", weekly_data(visited=True)
        )
        self.assertTrue(
            self.virtual_play(
                lambda: self.worker._watch_clip(
                    self.streamer, "weekly", baseline, self.clip
                )
            )
        )
        self.twitch.load_channel_points_context.assert_called_once_with(self.streamer)
        self.assertFalse(self.streamer.missing_weekly_reward())

    def test_weekly_jobs_respect_points_limit(self):
        self.streamer.weekly_rewards = weekly()
        self.twitch._streamer_has_reached_points_limit.return_value = True
        self.assertFalse(self.worker._job_active(self.streamer, "weekly"))
        self.streamer.streak_recovery = recovery()
        self.assertTrue(self.worker._job_active(self.streamer, "recovery"))

    def test_global_switches_disable_all_eligibility_queries(self):
        self.worker.weekly_rewards = False
        self.worker.watch_streak_recovery = False
        self.worker.scan_once()
        self.twitch.post_gql_request.assert_not_called()

    def test_accepted_playback_does_not_mean_recovery_success(self):
        self.streamer.streak_recovery = recovery()
        self.twitch.post_gql_request.return_value = response(
            "watchStreakMilestone", milestone()
        )
        self.assertFalse(
            self.virtual_play(
                lambda: self.worker._watch_clip(
                    self.streamer, "recovery", recovery(), self.clip
                )
            )
        )

    def test_stop_prevents_playback_post(self):
        self.streamer.streak_recovery = recovery()
        self.worker.stop()
        self.assertFalse(self.worker._send(self.streamer, "recovery", []))
        self.twitch._request_with_retry.assert_not_called()

    def test_stop_during_clip_wait_prevents_second_post(self):
        self.streamer.streak_recovery = recovery()
        with patch.object(
            self.worker, "_wait", side_effect=lambda _: self.worker.stop()
        ):
            self.assertFalse(
                self.worker._watch_clip(
                    self.streamer, "recovery", recovery(), self.clip
                )
            )
        self.assertEqual(self.twitch._request_with_retry.call_count, 1)

    def test_vod_access_rejects_subscriber_only_and_invalid_playlist(self):
        self.twitch.post_gql_request.return_value = {
            "data": {"videoPlaybackAccessToken": {"signature": "sig", "value": "a&b"}}
        }
        for status, text, expected in (
            (403, "", False),
            (200, "error", False),
            (200, "#EXTM3U\nvariant.m3u8", True),
        ):
            self.twitch._request_with_retry.return_value = Mock(
                status_code=status, text=text
            )
            self.twitch._last_http_url_from_playlist.return_value = (
                "https://example.test/variant.m3u8"
            )
            self.assertEqual(
                self.worker._vod_viewable(self.streamer, self.vod), expected
            )
        self.assertEqual(
            self.twitch._request_with_retry.call_args.kwargs["params"],
            {"sig": "sig", "token": "a&b"},
        )

    def test_vod_uses_real_intervals_and_api_confirmation(self):
        self.streamer.streak_recovery = recovery()
        self.twitch.post_gql_request.side_effect = [
            response("watchStreakMilestone", milestone())
        ] * 4 + [response("watchStreakMilestone", milestone(missed=False))]
        self.assertTrue(
            self.virtual_play(
                lambda: self.worker._watch_vod(
                    self.streamer, "recovery", recovery(), self.vod
                )
            )
        )
        self.assertEqual(self.twitch._request_with_retry.call_count, 2)
        payload = json.loads(
            base64.b64decode(
                self.twitch._request_with_retry.call_args.kwargs["data"]["data"]
            )
        )[0]
        self.assertFalse(payload["properties"]["live"])
        self.assertEqual(payload["properties"]["vod_id"], "999")

    def test_recovered_count_does_not_claim_new_broadcast(self):
        self.streamer.watch_streak_cache = Mock()
        self.streamer.watch_streak_account = "test"
        self.twitch.post_gql_request.return_value = response(
            "watchStreakMilestone", milestone(missed=False)
        )
        self.assertTrue(self.worker._confirmed(self.streamer, "recovery", recovery()))
        call = self.streamer.watch_streak_cache.set_streamer_status.call_args
        self.assertEqual(call.kwargs["watch_streak_days"], 3)
        self.assertFalse(call.kwargs["watch_streak_detected"])
        self.streamer.watch_streak_cache.mark_claimed.assert_not_called()

    def test_recovery_matches_broadcast_then_falls_back_to_viewable_vod(self):
        self.streamer.streak_recovery = recovery()
        unrelated = replace(self.clip, broadcast_id="unrelated")
        inaccessible = replace(self.vod, id="998")
        with (
            patch.object(
                self.worker, "refresh_streak_recovery", return_value=recovery()
            ),
            patch.object(
                self.worker,
                "_replays",
                side_effect=[[unrelated], [self.clip], [inaccessible, self.vod]],
            ),
            patch.object(self.worker, "_watch_clip", return_value=False) as clip_watch,
            patch.object(self.worker, "_vod_viewable", side_effect=[False, True]),
            patch.object(self.worker, "_watch_vod", return_value=True) as vod_watch,
        ):
            self.assertTrue(self.worker._attempt(self.streamer, "recovery"))
        self.assertEqual(clip_watch.call_args.args[3], self.clip)
        self.assertEqual(vod_watch.call_args.args[3], self.vod)

    def test_inactive_or_disabled_features_do_not_query_replays(self):
        self.twitch.post_gql_request.return_value = response("weeklyVisitRewards", None)
        self.streamer.settings.watch_streak_recovery = False
        with patch.object(self.worker, "_attempt") as attempt:
            self.worker.scan_once()
        attempt.assert_not_called()
        self.assertEqual(self.twitch.post_gql_request.call_count, 1)
        self.twitch.post_gql_request.reset_mock()
        self.streamer.settings.weekly_rewards = False
        self.worker.scan_once()
        self.twitch.post_gql_request.assert_not_called()

    def test_recovery_jobs_precede_weekly_and_retry_is_throttled(self):
        self.streamer.weekly_rewards = weekly()
        self.streamer.streak_recovery = recovery()
        with (
            patch.object(
                self.worker,
                "refresh_weekly_rewards",
                return_value=self.streamer.weekly_rewards,
            ),
            patch.object(
                self.worker,
                "refresh_streak_recovery",
                return_value=self.streamer.streak_recovery,
            ),
            patch.object(self.worker, "_attempt", return_value=False) as attempt,
        ):
            self.worker.scan_once()
            self.worker.scan_once()
        self.assertEqual(
            [call.args[1] for call in attempt.call_args_list], ["recovery", "weekly"]
        )

    def test_online_weekly_eligibility_uses_live_watcher(self):
        self.streamer.is_online = True
        with (
            patch.object(
                self.worker, "refresh_weekly_rewards", return_value=weekly()
            ) as refresh,
            patch.object(self.worker, "refresh_streak_recovery") as streak,
            patch.object(self.worker, "_attempt") as attempt,
        ):
            self.worker.scan_once()
        refresh.assert_called_once()
        streak.assert_not_called()
        attempt.assert_not_called()

    def test_worker_shutdown_interrupts_long_scan_sleep(self):
        scanned = Event()
        self.worker.settings = RewardAutomationSettings(scan_interval_seconds=3600)
        with patch.object(self.worker, "scan_once", side_effect=scanned.set):
            self.worker.start()
            self.assertTrue(scanned.wait(1))
            self.worker.stop()
            self.worker.join(1)
        self.assertFalse(self.worker.is_alive())

    def test_weekly_priority_stays_after_drops_and_ignores_completed_visit(self):
        twitch = Twitch("test", "ua")
        streamers = [
            self.streamer,
            Streamer("drop", self.streamer.settings),
            Streamer("weekly", self.streamer.settings),
        ]
        streamers[2].weekly_rewards = weekly()
        with (
            patch.object(
                Streamer,
                "drops_condition",
                autospec=True,
                side_effect=lambda streamer: streamer.username == "drop",
            ),
            patch.object(Twitch, "_drop_progress_value", return_value=0),
        ):
            keys = {
                index: twitch._priority_sort_key(
                    streamers,
                    index,
                    [Priority.DROPS, Priority.WEEKLY_REWARDS, Priority.ORDER],
                    {0: 0, 1: 1, 2: 2},
                    time.time(),
                )
                for index in range(3)
            }
        self.assertEqual(sorted(keys, key=keys.get), [1, 2, 0])
        streamers[2].weekly_rewards = replace(
            streamers[2].weekly_rewards, visited_today=True
        )
        self.assertEqual(
            twitch._priority_candidates(
                streamers, [0, 1, 2], Priority.WEEKLY_REWARDS, time.time()
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
