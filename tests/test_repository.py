from __future__ import annotations

from datetime import datetime, timezone

from mira_protect.repository import Repository
from mira_protect.schemas import AIAsset, AssetKind


def test_asset_first_seen_is_preserved_across_updates() -> None:
    repository = Repository("sqlite+pysqlite:///:memory:")
    asset = AIAsset(kind=AssetKind.DEVICE, name="linux-test")
    first_seen = asset.first_seen

    saved = repository.save_asset(asset)
    saved.owner = "updated-owner"
    saved.last_seen = datetime.now(timezone.utc)
    updated = repository.save_asset(saved)

    assert updated.first_seen == first_seen
    assert updated.owner == "updated-owner"
    assert repository.list_assets()[0].first_seen == first_seen
