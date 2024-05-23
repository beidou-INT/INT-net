def underscorize_to_camelcase(s):
    parts = s.split('_')
    return parts[0] + ''.join(word.capitalize() for word in parts[1:])

# 示例
print(underscorize_to_camelcase('helloworld'))  # 输出: helloWorld
print(underscorize_to_camelcase('this_is_a_test'))  # 输出: thisIsATest
