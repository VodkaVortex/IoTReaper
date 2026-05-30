import configparser
import json
import os
import logging

from openai import OpenAI


class Chatbot:
    def __init__(self, config_file='config.ini', chat_type="source", gpt_model=None, api_key_prefix='LLM'):
        self.config = self.load_config(config_file)
        self.api_key_prefix = api_key_prefix
        self.api_key = self.config[api_key_prefix]['api_key']
        self.base_url = self.config[api_key_prefix]['base_url']
        self.gpt_model = gpt_model

        # 根据 chat_type 选择不同的 session 文件 & 标记
        if chat_type == "source":
            self.session_file_path = self.config['Session']['source_session']
            self.flag = "source"
        elif chat_type == "sink":
            self.session_file_path = self.config['Session']['sink_session']
            self.flag = "sink"
        elif chat_type == "vul":
            self.session_file_path = self.config['Session']['vul_session']
            self.flag = "vul"
        elif chat_type == "other":
            self.session_file_path = ""
            self.flag = "other"
        else:
            # 一个兜底
            self.session_file_path = ""
            self.flag = "request"

        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)
        self.messages = self.load_messages()

    def load_config(self, config_file):
        config = configparser.ConfigParser()
        config.read(config_file)
        return config

    def load_messages(self):
        if os.path.exists(self.session_file_path):
            with open(self.session_file_path, "r", encoding="utf-8") as file:
                messages = json.load(file)
        else:
            messages = [{"role": "system", "content": "You are a http protocol expert..."}]
        return messages

    def multi_line_input(self, prompt="Input Your Question: ", terminator="END"):
        print(prompt + " (Type '{}' and press Enter to finish)".format(terminator))
        lines = []
        while True:
            line = input()
            if line.strip() == terminator:
                break
            lines.append(line)
        return "\n".join(lines)

    def read_from_file(self):
        filename = input("Please enter the filename: ")
        try:
            with open(filename, 'rb') as file:
                content = file.read()
                return content.decode('utf-8')
        except FileNotFoundError:
            logging.error(f"File {filename} not found.")
            return ''
        except Exception as e:
            logging.error(f"An error occurred while reading the file: {e}")
            return ''

    def chat(self, user_input):
        tmp_messages = self.messages.copy()
        tmp_messages.append({"role": "user", "content": user_input})

        model = self.config[self.api_key_prefix]['model'] if self.gpt_model is None else self.gpt_model

        try:
            response = self.client.chat.completions.create(
                model=model,
                messages=tmp_messages,
                max_tokens=int(self.config[self.api_key_prefix]['max_tokens']),
                temperature=float(self.config[self.api_key_prefix]['temperature']),
                top_p=float(self.config[self.api_key_prefix]['top_p']),
                n=int(self.config[self.api_key_prefix]['n']),
            )
        except Exception as e:
            logging.error(f"GPT LLM Request error: {e}")
            return b'error'

        try:
            response_text = response.choices[0].message.content
            response_text = response_text.strip()
            # CRLF conversion
            if '\r\n' not in response_text:
                response_text = response_text.replace('\n', '\r\n')
            response_text = response_text + '\r\n\r\n'
            return response_text.encode("utf-8")
        except Exception as e:
            logging.error(f"Response parse error: {e}")
            return b'error'


def main():
    chatbot = Chatbot(config_file="config/config.ini", chat_type="source")
    while True:
        user_input = chatbot.multi_line_input()
        response = chatbot.chat(user_input)
        print(response.decode("utf-8", errors="ignore"))


if __name__ == "__main__":
    main()
