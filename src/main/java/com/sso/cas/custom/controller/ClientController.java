package com.sso.cas.custom.controller;

import org.apereo.cas.services.RegexRegisteredService;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.ReturnAllAttributeReleasePolicy;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.bind.annotation.*;

import java.net.URL;

/**
 * @ClassName: ClientRegisterController
 * @Description: 动态服务注册接口，参考：https://blog.csdn.net/qq_34021712/article/details/81638090
 * @Author: LaoJiang
 * @Date: 2020/2/13 0013 16:48
 * @Version: 1.0
 */
@RestController
public class ClientController {

    @Autowired
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;

    /**
     * 添加service
     * @param serviceId 域名
     * @param id
     * @return
     */
    @RequestMapping(value = "/addClient/{serviceId}/{id}",method = RequestMethod.GET)
    public Object addClient(@PathVariable("serviceId") String serviceId, @PathVariable("id") int id) {
        try {
            ReturnMessage returnMessage = new ReturnMessage();
            String a="^(https|http|imaps)://"+serviceId+".*";

            RegisteredService registeredService = servicesManager.findServiceBy("http://"+serviceId);
            if(registeredService != null){
                returnMessage.setCode(200);
                returnMessage.setMessage("此service已注册");
                return returnMessage;
            }

            RegexRegisteredService service = new RegexRegisteredService();
            ReturnAllAttributeReleasePolicy re = new ReturnAllAttributeReleasePolicy();
            service.setServiceId(a);
            service.setId(id);
            service.setAttributeReleasePolicy(re);
            service.setName(serviceId);
            //这个是为了单点登出而作用的
            service.setLogoutUrl(new URL("http://"+serviceId));
            servicesManager.save(service);
            //执行load让他生效
            servicesManager.load();

            returnMessage.setCode(200);
            returnMessage.setMessage("添加成功");
            return returnMessage;
        } catch (Exception e) {

            ReturnMessage returnMessage = new ReturnMessage();
            returnMessage.setCode(500);
            returnMessage.setMessage("添加失败");
            return returnMessage;
        }
    }

    /**
     * 删除service
     * @param serviceId
     * @return
     */
    @RequestMapping(value = "/deleteClient",method = RequestMethod.GET)
    public Object deleteClient(@RequestParam("serviceId") String serviceId) {
        try {
            RegisteredService service = servicesManager.findServiceBy(serviceId);
            ReturnMessage returnMessage = new ReturnMessage();
            if(service!=null){
                servicesManager.delete(service);
                //执行load生效
                servicesManager.load();
                returnMessage.setCode(200);
                returnMessage.setMessage("删除成功");
            }else{
                returnMessage.setCode(200);
                returnMessage.setMessage("此service未注册");
            }

            return returnMessage;
        } catch (Exception e) {
            //数据库也删了
            e.printStackTrace();
            ReturnMessage returnMessage = new ReturnMessage();
            returnMessage.setCode(500);
            returnMessage.setMessage("删除失败");
            return returnMessage;
        }
    }


    class ReturnMessage{

        private Integer code;

        private String message;

        public Integer getCode() {
            return code;
        }

        public void setCode(Integer code) {
            this.code = code;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }
}



