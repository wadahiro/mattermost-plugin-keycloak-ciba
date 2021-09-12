<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("smsVerifyTitle")}
    <#elseif section = "form">
        <form id="kc-sms-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <div class="${properties.kcFormOptionsWrapperClass!}">
                    </div>
                </div>

                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <div class="${properties.kcFormButtonsWrapperClass!}">
                        <#if isAppInitiatedAction??>
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("continue")}" />
                        <a class="${properties.kcButtonClass!} ${properties.kcButtonLargeClass!}" href="${url.loginRestartFlowUrl}" />${msg("doCancel")}</a>
                        <#else>
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("continue")}"/>
                        <a class="${properties.kcButtonClass!} ${properties.kcButtonLargeClass!}" href="${url.loginRestartFlowUrl}" />${msg("doCancel")}</a>
                        </#if>
                    </div>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
