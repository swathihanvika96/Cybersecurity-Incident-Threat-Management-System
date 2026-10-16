import pytest

from app.schemas.examples import EXAMPLES, _request_models, apply_examples

MODELS = _request_models()


def test_every_request_model_has_an_example():
    missing = sorted(set(MODELS) - set(EXAMPLES))
    assert not missing, f"add Swagger examples for: {missing}"


@pytest.mark.parametrize("name", sorted(EXAMPLES))
def test_example_is_valid_for_its_model(name):
    MODELS[name].model_validate(EXAMPLES[name])


def test_examples_are_exposed_in_openapi(client):
    apply_examples()
    spec = client.get("/openapi.json").json()
    user = spec["components"]["schemas"]["UserCreate"]
    assert user["examples"][0]["full_name"] == "Swathi" and user["examples"][0]["phone"] == "9876543210"
