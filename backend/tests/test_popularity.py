from app.config import settings
from app.features import popularity


def test_popularity_rank_lookup(tmp_path):
    cache_file = tmp_path / "tranco.csv"
    cache_file.write_text("1,google.com\n2,example.com\n", encoding="utf-8")

    original_path = settings.tranco_list_path
    settings.tranco_list_path = cache_file
    popularity.clear_cache()
    try:
        assert popularity.popularity_rank("https://www.google.com/search") == 1
        assert popularity.popularity_rank("https://example.com") == 2
        assert popularity.popularity_rank("https://not-in-the-list.com") is None
    finally:
        settings.tranco_list_path = original_path
        popularity.clear_cache()


def test_popularity_rank_missing_cache_file(tmp_path):
    missing_path = tmp_path / "does-not-exist.csv"
    original_path = settings.tranco_list_path
    settings.tranco_list_path = missing_path
    popularity.clear_cache()
    try:
        assert popularity.popularity_rank("https://example.com") is None
    finally:
        settings.tranco_list_path = original_path
        popularity.clear_cache()
