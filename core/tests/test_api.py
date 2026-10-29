from datetime import timedelta

from honeyjar.api import all_bucket


def test_all_time_bucket_follows_history_length():
    # a young honeynet still gets a real curve instead of a single daily point
    assert all_bucket(timedelta(hours=2)) == timedelta(minutes=1)
    assert all_bucket(timedelta(hours=18)) == timedelta(minutes=5)
    assert all_bucket(timedelta(days=7)) == timedelta(hours=1)
    assert all_bucket(timedelta(days=90)) == timedelta(hours=12)
    assert all_bucket(timedelta(days=3650)) == timedelta(days=7)
