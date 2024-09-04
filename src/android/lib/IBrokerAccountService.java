package com.cordova.plugin.oidc;
import android.os.Bundle;
import android.content.Intent;
import java.util.Map;

/**
 * Broker Account service APIs provided by the broker app. Those APIs will be responsible for interacting with the
 * account manager API. Calling app does not need to request for contacts permission if the broker installed on the
 * device has the support for the bound service.
 */
interface IBrokerAccountService {

    Bundle getBrokerUsers();
    
    Bundle acquireTokenSilently(Map<String, String> requestParameters);
    
    Intent getIntentForInteractiveRequest();

    void removeAccounts();
}
