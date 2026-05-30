from unittest.mock import MagicMock, patch
import pytest


def _make_ini(tmp_path, extra=""):
    ini = tmp_path / "config.ini"
    ini.write_text(f"""
[LLM]
api_key = test-key
base_url = https://relay.example.com/v1
model = gpt-4o-mini
max_tokens = 100
temperature = 0.5
top_p = 1
n = 1

[Session]
source_session = /nonexistent_source.json
sink_session = /nonexistent_sink.json
vul_session = /nonexistent_vul.json
{extra}
""")
    return str(ini)


def test_chatbot_uses_openai_with_relay(tmp_path):
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "***nvram_get***"

    with patch("core.llm.llm_request.OpenAI") as MockOpenAI:
        mock_client = MagicMock()
        MockOpenAI.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_response

        from core.llm.llm_request import Chatbot
        bot = Chatbot(config_file=_make_ini(tmp_path), chat_type="other")
        result = bot.chat("test input")

    MockOpenAI.assert_called_once_with(api_key="test-key", base_url="https://relay.example.com/v1")
    assert b"nvram_get" in result


def test_chatbot_returns_error_on_exception(tmp_path):
    with patch("core.llm.llm_request.OpenAI") as MockOpenAI:
        mock_client = MagicMock()
        MockOpenAI.return_value = mock_client
        mock_client.chat.completions.create.side_effect = Exception("connection refused")

        from core.llm.llm_request import Chatbot
        bot = Chatbot(config_file=_make_ini(tmp_path), chat_type="other")
        result = bot.chat("test")

    assert result == b"error"
