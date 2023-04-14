matchers 的type参数定义如下：

1. status, match HTTP response status codes;
2. size, match length, such as Content-Length;
3. word, match strings;
4. regex, match regular expressions;
5. binary, match binary data;
6. dsl, use complex expressions for matching.



There are several types of extractors:

1. regex, regular extraction;
2. kval, key-value pair, such as extracting the specified response header;
3. json, use jq syntax to extract json data;
4. xpath, use xpath to extract html response data;
5. dsl, using expression extraction, not commonly used.



interactsh_protocol info:

1. `interactsh_protocol` - Value can be `dns`, `http` or `smtp`. This is the standard matcher for every interactsh based template with `dns` often as the common value as it is very non-intrusive in nature.

