from common import canonical_library_id, canonical_release, compare_versions, find_nearest_safe, is_ga_release


def test_canonical_release_strips_tag_v_for_registry_versions():
    assert canonical_release("pypi", "v0.8.8") == "0.8.8"
    assert canonical_release("npm", "V1.2.3") == "1.2.3"
    assert canonical_release("maven", "v1.2.3") == "v1.2.3"
    assert canonical_library_id("pypi||requests|v0.8.8") == "pypi||requests|0.8.8"


def test_is_ga_release_accepts_ga_variants():
    assert is_ga_release("5.3.39")
    assert is_ga_release("4.1.100.Final")
    assert is_ga_release("4.1.100.RELEASE")


def test_is_ga_release_rejects_non_ga_variants():
    assert not is_ga_release("5.3.39-SNAPSHOT")
    assert not is_ga_release("5.3.39-RC1")
    assert not is_ga_release("1.2.3-atlassian-4")
    assert not is_ga_release("2.0.0-m01")


def test_compare_versions_maven_and_rpm():
    assert compare_versions("maven", "5.3.39", "5.3.40") == -1
    assert compare_versions("maven", "6.0.0", "5.3.40") == 1
    assert compare_versions("rpm", "5.4.5-1", "5.4.6-2") == -1
    assert compare_versions("rpm", "1:5.4.6-2", "5.4.6-2") == 1


def test_find_nearest_safe_prefers_ga_and_higher_only():
    chain = [
        {"release": "5.3.39", "max_cvss": 9.8},
        {"release": "5.3.40-RC1", "max_cvss": 0.0},
        {"release": "5.3.40", "max_cvss": 5.3},
        {"release": "6.0.0", "max_cvss": 0.0},
        {"release": "6.0.23", "max_cvss": 0.0},
    ]
    nearest, max_patch, distance = find_nearest_safe("maven", "5.3.39", chain)
    assert nearest == "5.3.40"
    assert max_patch == "5.3.40"
    assert distance == "PATCH"


def test_find_nearest_safe_dead_end():
    chain = [{"release": "1.0.0", "max_cvss": 9.8}, {"release": "1.0.1", "max_cvss": 8.0}]
    nearest, max_patch, distance = find_nearest_safe("maven", "1.0.0", chain)
    assert nearest is None
    assert max_patch is None
    assert distance == "DEAD_END"
