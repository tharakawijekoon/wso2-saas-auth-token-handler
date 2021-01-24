package org.wso2.custom.saas.auth.handler.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.custom.saas.auth.handler.SaaSAccessTokenHandler;

@Component(
        name = "org.wso2.custom.saas.auth.handler",
        immediate = true)
public class SaaSAuthServiceComponent {

    private static final Log log = LogFactory.getLog(org.wso2.custom.saas.auth.handler.internal.SaaSAuthServiceComponent.class);

    @Activate
    protected void activate(ComponentContext cxt) {
        try {
            cxt.getBundleContext().registerService(AuthenticationHandler.class, new SaaSAccessTokenHandler(), null);
            if (log.isDebugEnabled())
                log.debug("SaaSAuthService is activated");
        } catch (Throwable e) {
            log.error(e.getMessage(), e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("SaaSAuthService bundle is deactivated");
        }
    }

//    @Reference(
//            name = "user.realmservice.default",
//            service = org.wso2.carbon.user.core.service.RealmService.class,
//            cardinality = ReferenceCardinality.MANDATORY,
//            policy = ReferencePolicy.DYNAMIC,
//            unbind = "unsetRealmService")
//    protected void setRealmService(RealmService realmService) {
//        if (log.isDebugEnabled()) {
//            log.debug("RealmService acquired");
//        }
//        AuthenticationServiceHolder.getInstance().setRealmService(realmService);
//    }
//
//    protected void unsetRealmService(RealmService realmService) {
//        setRealmService(null);
//    }

}