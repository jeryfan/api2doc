import json

from mitmproxy.http import HTTPFlow
from mitmproxy.tools import main

hook_domain = "api.powthink.com/platform"
request_header = "| 参数名 | 参数类型 | 参数说明 | 是否必填 | 说明 |\n"
request_separator = "| --- | --- | --- | --- | --- |\n"
response_header = "| 参数名 | 参数说明 | 类型 |\n"
response_separator = "| --- | --- | --- |\n"


class Hook:

    def gen_request_header(self, flow: HTTPFlow):

        content = "##### 接口名称\n" + " \n"
        content = content + "###### 说明\n"
        content = content + f"url：{flow.request.pretty_url.replace('https://api.powthink.com', '').split('?', 1)[0]}\n"
        content = content + f"方法：{flow.request.method.upper()}	{flow.request.headers.get('Content-Type', 'application/json')}\n"
        content = content + "###### 输入参数 \n" + request_header + request_separator
        return content

    def gen_response_header(self, flow: HTTPFlow):
        content = "###### 输出参数 \n"
        content += response_header
        content += response_separator
        return content

    def gen_example(self, response):
        content = '###### 返回结果示例\n'
        json_data = json.dumps(response, ensure_ascii=False, indent=4)
        markdown_text = f'```json\n{json_data}\n```'
        return content + markdown_text

    def request(self, flow: HTTPFlow):
        if hook_domain in flow.request.url:
            content = self.gen_request_header(flow)

            # 查询参数
            for parama_name, parama_value in flow.request.query.items():
                row = f"| {parama_name} | {type(parama_value).__name__} |   |   |   |\n"
                content += row

            # 处理表单
            form_data = flow.request.urlencoded_form
            # print('----------------', form_data)
            if form_data:
                for parama_name, parama_value in form_data.items(multi=True):
                    row = f"| {parama_name} | {type(parama_value).__name__} |   |   |   |\n"
                    content += row

            # 处理payload
            try:
                json_data = flow.request.json()
                if json_data:
                    for parama_name, parama_value in json_data.items():
                        row = f"| {parama_name} | {type(parama_value).__name__} |   |   |   |\n"
                        content += row
            except:
                pass
            content += "\n"

            with open("api.md", encoding='utf-8', mode='a') as fp:
                fp.write(content)

    def response(self, flow: HTTPFlow):
        if hook_domain in flow.request.url:
            content = self.gen_response_header(flow)
            # 响应体
            resp = flow.response.json()
            if "data" in resp:
                data = resp["data"]
                dict_list = []
                array_list = []
                if data:
                    # 如果data是字典
                    if type(data) == dict:
                        # 处理普通类型字段
                        for parama_name, parama_value in data.items():
                            if type(parama_value) == dict:
                                dict_list.append(parama_name)
                                continue
                            if type(parama_value) == list:
                                array_list.append(parama_name)
                                continue
                            row = f"| {parama_name} |  | {type(parama_value).__name__} |\n"
                            content += row
                        # 处理嵌套字典字段，仅处理一层
                        if dict_list:
                            for field in dict_list:
                                example = data[field]
                                content += f"| {field} |  | {type(data[field]).__name__} |\n"
                                for parama_name, parama_value in example.items():
                                    row = f"| {field}.{parama_name} |  | {type(parama_value).__name__} |\n"
                                    content += row

                        # 处理嵌套数组字段，仅处理一层
                        if array_list:
                            for field in array_list:
                                content += f"| {field} |  | {type(data[field]).__name__} |\n"
                                example = data[field][0]
                                if type(example) == dict:
                                    for parama_name, parama_value in example.items():
                                        row = f"| {field}[0].{parama_name} |  | {type(parama_value).__name__} |\n"
                                        content += row
                                else:
                                    row = f"| {field} |  | {type(data[field]).__name__} |\n"
                                    content += row
                    elif type(data) == list:
                        example = data[0]
                        if type(example) == dict:
                            for parama_name, parama_value in example.items():
                                row = f"| {parama_name} |  | {type(parama_value).__name__} |\n"
                                content += row
                content += self.gen_example(resp)
                content += "\n"

                with open("api.md", encoding='utf-8', mode='a') as fp:
                    fp.write(content)


addons = [Hook()]

if __name__ == '__main__':
    main.mitmdump(['-s', __file__, '--listen-host', '127.0.0.1', '-p', '8080', '--set', 'block_global=false'])
