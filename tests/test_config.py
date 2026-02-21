from secure_inspector.config import (
    PipelineConfig,
    ProfileConfig,
    should_enable_extra_agent,
    specialist_category_map,
)


def test_specialist_category_map_routes_extra():
    profile = ProfileConfig(
        core_categories={
            "injection": {"categories": ["A03:2021-Injection"]},
            "access_control": {"categories": ["A01:2021-Broken Access Control"]},
        },
        extra_categories=["A02:2021-Cryptographic Failures"],
    )
    mapping = specialist_category_map(profile)
    assert "A03:2021-Injection" in mapping["InjectionSpecialistAgent"]
    assert "A01:2021-Broken Access Control" in mapping["AccessControlSpecialistAgent"]
    assert "A02:2021-Cryptographic Failures" in mapping["ExtraCategorySpecialistAgent"]


def test_extra_agent_toggle_respects_pipeline():
    profile = ProfileConfig(
        core_categories={
            "injection": {"categories": ["A03:2021-Injection"]},
            "access_control": {"categories": ["A01:2021-Broken Access Control"]},
        },
        extra_categories=["A02:2021-Cryptographic Failures"],
    )
    assert should_enable_extra_agent(profile, PipelineConfig(allow_extra_agent=True))
    assert not should_enable_extra_agent(profile, PipelineConfig(allow_extra_agent=False))

