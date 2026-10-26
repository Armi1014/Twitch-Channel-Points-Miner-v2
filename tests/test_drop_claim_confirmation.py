import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from TwitchChannelPointsMiner.classes.Settings import Events
from TwitchChannelPointsMiner.classes.Twitch import Twitch


MODULE = "TwitchChannelPointsMiner.classes.Twitch"


class DropClaimConfirmationTest(unittest.TestCase):
    def setUp(self):
        self.cache = tempfile.TemporaryDirectory()
        self.addCleanup(self.cache.cleanup)
        self.twitch = self.new_twitch()
        self.drop = SimpleNamespace(
            id="reward-id", drop_instance_id="instance-1", name="Same name",
            benefit="Reward", minutes_required=60,
        )
        self.logger = patch(MODULE + ".logger").start()
        self.addCleanup(patch.stopall)

    def new_twitch(self, account="test"):
        with patch(MODULE + ".Path.absolute", return_value=Path(self.cache.name)):
            return Twitch(account, "ua")

    @staticmethod
    def response(status="ELIGIBLE_FOR_ALL"):
        return {"data": {"claimDropRewards": {"status": status}}}

    @staticmethod
    def inventory(claimed=False, instance="instance-1", drop_id="reward-id"):
        return {"data": {"currentUser": {"inventory": {"dropCampaignsInProgress": [
            {"timeBasedDrops": [{"id": drop_id, "self": {
                "dropInstanceID": instance, "isClaimed": claimed,
            }}]},
        ]}}}}

    def notifications(self):
        return [call for call in self.logger.info.call_args_list
                if call.kwargs.get("extra", {}).get("event") == Events.DROP_CLAIM]

    def test_false_success_is_not_announced_or_retried_every_poll(self):
        with patch.object(Twitch, "post_gql_request", side_effect=[
            self.response(), self.inventory(False), self.inventory(False),
        ]) as post:
            self.assertFalse(self.twitch.claim_drop(self.drop))
            self.assertFalse(self.twitch.claim_drop(self.drop))
            self.twitch._Twitch__get_inventory()
            self.assertFalse(self.twitch.claim_drop(self.drop))
        self.assertEqual(post.call_count, 3)
        self.assertEqual(len(self.notifications()), 0)
        self.logger.warning.assert_called_once()

    def test_confirmed_success_is_announced_once_with_reward_details(self):
        with patch.object(Twitch, "post_gql_request", side_effect=[
            self.response(), self.inventory(True), self.inventory(False),
        ]) as post:
            self.assertTrue(self.twitch.claim_drop(self.drop))
            self.twitch._Twitch__get_inventory()  # A stale snapshot must not undo confirmation.
            self.assertTrue(self.twitch.claim_drop(self.drop))
        self.assertEqual(post.call_count, 3)
        self.assertEqual(len(self.notifications()), 1)
        self.assertEqual(self.notifications()[0].kwargs["extra"]["discord_details"], {
            "drop_name": "Same name", "reward": "Reward", "minutes_required": 60,
        })

    def test_pending_claim_is_confirmed_after_restart_even_without_instance_id(self):
        with patch.object(Twitch, "post_gql_request", side_effect=[self.response(), {}]):
            self.assertFalse(self.twitch.claim_drop(self.drop))
        restarted = self.new_twitch()
        with patch.object(Twitch, "post_gql_request", return_value=self.inventory(True, instance=None)):
            restarted._Twitch__get_inventory()
        self.assertEqual(len(self.notifications()), 1)
        restarted = self.new_twitch()
        with patch.object(Twitch, "post_gql_request") as post:
            self.assertTrue(restarted.claim_drop(self.drop))
        post.assert_not_called()
        self.assertEqual(len(self.notifications()), 1)

    def test_cooldown_survives_restart_and_allows_later_retry(self):
        with patch(MODULE + ".time.time", return_value=1000), patch.object(
            Twitch, "post_gql_request", side_effect=[self.response(), self.inventory(False)],
        ):
            self.assertFalse(self.twitch.claim_drop(self.drop))
        restarted = self.new_twitch()
        with patch(MODULE + ".time.time", return_value=1800), patch.object(Twitch, "post_gql_request") as post:
            self.assertFalse(restarted.claim_drop(self.drop))
        post.assert_not_called()
        with patch(MODULE + ".time.time", return_value=1900), patch.object(
            Twitch, "post_gql_request", side_effect=[self.response(), self.inventory(True)],
        ) as post:
            self.assertTrue(restarted.claim_drop(self.drop))
        self.assertEqual(post.call_count, 2)
        self.assertEqual(len(self.notifications()), 1)

    def test_failed_or_already_claimed_requests_do_not_announce(self):
        for index, (response, expected) in enumerate([
            (self.response("DROP_INSTANCE_ALREADY_CLAIMED"), True),
            (self.response("NOT_ELIGIBLE"), False),
            ({"errors": [{"message": "Rejected"}]}, False),
            ({"data": {"claimDropRewards": None}}, False),
        ]):
            with self.subTest(response=response):
                self.drop.drop_instance_id = f"instance-{index}"
                with patch.object(Twitch, "post_gql_request", return_value=response) as post:
                    self.assertEqual(self.twitch.claim_drop(self.drop), expected)
                post.assert_called_once()
        self.assertEqual(len(self.notifications()), 0)

    def test_identical_names_on_distinct_instances_both_notify(self):
        for index in (1, 2):
            self.drop.drop_instance_id = f"instance-{index}"
            with patch.object(Twitch, "post_gql_request", side_effect=[
                self.response(), self.inventory(True, instance=self.drop.drop_instance_id),
            ]):
                self.assertTrue(self.twitch.claim_drop(self.drop))
        self.assertEqual(len(self.notifications()), 2)

    def test_wrong_instance_and_missing_inventory_do_not_confirm(self):
        with patch.object(Twitch, "post_gql_request", side_effect=[
            self.response(), self.inventory(True, instance="someone-else"), {},
            {"data": {"currentUser": {"inventory": {"dropCampaignsInProgress": []}}}},
        ]):
            self.assertFalse(self.twitch.claim_drop(self.drop))
            self.twitch._Twitch__get_inventory()
            self.twitch._Twitch__get_inventory()
        self.assertEqual(len(self.notifications()), 0)

    def test_cache_is_separate_for_each_account(self):
        with patch.object(Twitch, "post_gql_request", return_value=self.response("DROP_INSTANCE_ALREADY_CLAIMED")):
            self.assertTrue(self.twitch.claim_drop(self.drop))
        other = self.new_twitch("other")
        with patch.object(Twitch, "post_gql_request", side_effect=[self.response(), self.inventory(True)]):
            self.assertTrue(other.claim_drop(self.drop))
        self.assertEqual(len(self.notifications()), 1)


if __name__ == "__main__":
    unittest.main()
