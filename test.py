class Tool(object):
    #使用赋值语句定义类属性，
    count=0

    @classmethod
    def show_tool_count(cls):
        print("工具对象的数量 %d"%cls.count)


    def __init__(self,name):
        self.name = name
        #让类属性的值+1
        Tool.count+=1

# # 创建实例对象
tool1= Tool("aaaa")
tool2=Tool("bbbb")
# tool2= Tool("aaaa")
# tool3= Tool("aaaa")
# tool3.count=6 #赋值语句，会在tool3对象中增加count属性
# print(tool3.count)
# print(Tool.count)
# 调用类方法
Tool.show_tool_count()