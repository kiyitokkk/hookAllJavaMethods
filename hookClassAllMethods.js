
var ByteString = Java.use("com.android.okhttp.okio.ByteString");
function logInf(classs){
    Java.perform(function (){
        var Modifier = Java.use("java.lang.reflect.Modifier");
        var Field = Java.use("java.lang.reflect.Field");
        var modifiers = classs.getModifiers();
        classs.setAccessible(true);
        if (Modifier.isStatic(modifiers)) {
            // 静态字段
            var value = classs.get(null);
            console.log('\x1B[36m\x1B[1m', classs + " =>"  + value)
        } else {
             console.log(classs)
        }
    })
}


function replace_str() {
    var pt_strstr = Module.findExportByName("libc.so", 'strstr');
    var pt_strcmp = Module.findExportByName("libc.so", 'strcmp');

    Interceptor.attach(pt_strstr, {
        onEnter: function (args) {
            var str1 = args[0].readCString();
            var str2 = args[1].readCString();
            if (
                str2.indexOf("REJECT") !== -1 ||
                str2.indexOf("tmp") !== -1 ||
                str2.indexOf("frida") !== -1 ||
                str2.indexOf("gum-js-loop") !== -1 ||
                str2.indexOf("gmain") !== -1 ||
                str2.indexOf("linjector") !== -1
            ) {
                this.hook = true;
            }
        }, onLeave: function (retval) {
            if (this.hook) {
                retval.replace(0);
            }
        }
    });

    Interceptor.attach(pt_strcmp, {
        onEnter: function (args) {
            var str1 = args[0].readCString();
            var str2 = args[1].readCString();
            if (
                str2.indexOf("REJECT") !== -1 ||
                str2.indexOf("tmp") !== -1 ||
                str2.indexOf("frida") !== -1 ||
                str2.indexOf("gum-js-loop") !== -1 ||
                str2.indexOf("gmain") !== -1 ||
                str2.indexOf("linjector") !== -1
            ) {
                //console.log("strcmp-->", str1, str2);
                this.hook = true;
            }
        }, onLeave: function (retval) {
            if (this.hook) {
                retval.replace(0);
            }
        }
    })

}
function hook_open(){
    var open_addr = Module.findExportByName("libc.so","fopen")
    var io_map=Memory.allocUtf8String("/proc/13254/maps");
    Interceptor.attach(open_addr,{
        onEnter:function (args){
            if (args[0].readCString().indexOf("/maps") != -1){
                // console.log("find maps sucess")
                args[0] = io_map
            }
            this.pathname=args[0]
            this.mode=args[0]
        },
        onLeave:function(retval){

        }
    })
}
function getAllsonClass(classs){
    console.log('\n')
    console.log('\x1B[36m\x1B[0m', "查询到子类  =>" + classs.getName())
    hookClass(String(classs.getName()))
}
var thisclass = null;
//"java.security.MessageDigest"
function hookClass(CLASS){
Java.perform(function(){
    var classStudent = Java.use(CLASS);
    var classs = classStudent.class;

    //获取所有内部类
    var innerClasses = classs.getDeclaredClasses();
    if(innerClasses.length > 0){
        innerClasses.forEach(getAllsonClass);
    }
    console.log('\x1B[36m\x1B[1m',"===========" + classs + "中的所有变量==============")
    //输出所有变量
    classs.getDeclaredFields().forEach(logInf)
    console.log('\x1B[36m\x1B[1m',"===========" + classs +  "的所有方法==============")
    //输出所有方法,并hook
    classs.getDeclaredMethods().forEach(function(method){
        console.log(method, "method")
       var methodsName = method.getName();
        try {
        var overloads  = classStudent[methodsName].overloads;
    //    console.log(overloads.length)
       for (var i=0; i< overloads.length; i++){
            overloads[i].implementation = function () {
            console.log('\n')
            console.warn('\x1B[34m\x1B[1m', "进入" + classs.getName() + "类的" + methodsName + "方法")
            var parameterTypes =  method.getParameterTypes();
            var return_type = method.getReturnType()
            for(var j=0; j<arguments.length; j++){
                console.error("\x1B[32m\x1B[1m", "参数" + j + " => " + arguments[j])
                if (typeof (arguments[j]) === "object"){
                    console.log('\x1B[32m\x1B[1m',"正在尝试打印object类型参数" + j  + "====>" + JSON.stringify(arguments[j]))
                }
                try {
                    if ( parameterTypes[j].getName() === '[B') {
                        console.log('\x1B[32m\x1B[1m',"尝试打印byte类型参数")
                        console.log('\x1B[32m\x1B[1m',"参数" + j + "字节数组转换为字符串结果为" +  (ByteString.of(arguments[j]).utf8()))
                    }
                }catch (e) {

                }

            }
            if (arguments.length === 0) {
              console.log("该函数无参数");
            }
            var result = this[methodsName].apply(this,arguments)

            if (return_type.getName() === "[B") {
                console.error("结果是 => " + result )
                console.error("尝试打印byte类型返回值")
                console.error("返回值字节数组转换为字符串结果为" +  (ByteString.of(result).utf8()))
            }else {
                console.error("结果是 => " + result )
            }
            return result;
            };
        }
        }catch {

        }
    })
    console.log('\n')
})
}
function bypass_frida() {
    // 反调试frida 可过frida的字符检测以及maps文件映射检测
    console.log("bypass frida is runing")
    hook_open()
    replace_str()
}







