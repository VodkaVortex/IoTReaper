def convert_to_c_string(text):
    escape_dict = {
        '\\': r'\\',
        '"': r'\"',
        '\n': r'\n',
        '\t': r'\t',
        '\r': r'\r'
    }
    escaped = []
    for char in text:
        if char in escape_dict:
            escaped.append(escape_dict[char])
        else:
            escaped.append(char)
    return '"' + ''.join(escaped) + '"'

# 原始文本
original_text = r"""
"""

print(convert_to_c_string(original_text))