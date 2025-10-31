<#macro registrationLayout bodyClass="" displayInfo=false displayWide=false>
<!DOCTYPE html>
<html lang="${locale}" dir="ltr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><#nested "title">Sky Genesis Login</#nested></title>
    <link rel="icon" href="${url.resourcesPath}/img/favicon.ico">
    <#if properties.styles?has_content>
        <#list properties.styles?split(' ') as style>
            <link href="${url.resourcesPath}/${style}" rel="stylesheet">
        </#list>
    </#if>
</head>
<body class="${bodyClass}">
    <#nested "form">
</body>
</html>
</#macro>