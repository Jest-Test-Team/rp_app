*** Settings ***
Documentation     Builds of the console app for each platform this machine can build, and
...               checks on the built artefacts (merged Android manifest, iOS Info.plist).
...               A platform whose toolchain is missing is skipped, not failed.
Resource          ../resources/app.resource
Test Tags         build    mobile

*** Test Cases ***
Android Debug APK
    Require Android SDK
    Pub Get
    Flutter    0    build    apk    --debug    timeout=40min
    File Should Exist    ${APP}/build/app/outputs/flutter-apk/app-debug.apk
    ${m}=    Merged Android Manifest
    Should Contain    ${m}    android:allowBackup="false"
    Should Contain    ${m}    android:usesCleartextTraffic="false"
    Should Contain    ${m}    android.permission.INTERNET

iOS App Without Code Signing
    Require Xcode
    Pub Get
    Flutter    0    build    ios    --debug    --no-codesign    timeout=40min
    # Built plists are binary: convert to XML first.
    ${p}=    Run Process    plutil    -convert    xml1    -o    -    ${APP}/build/ios/iphoneos/Runner.app/Info.plist
    ${plist}=    Set Variable    ${p.stdout}
    Should Contain    ${plist}    NSLocalNetworkUsageDescription
    Should Contain    ${plist}    _rp-security._tcp

macOS App
    Require Xcode
    Pub Get
    Flutter    0    build    macos    --debug    timeout=40min
    Directory Should Exist    ${APP}/build/macos/Build/Products/Debug/rp_console.app

Linux App
    ${linux}=    Is Linux
    Skip If    not ${linux}    Linux desktop builds need a Linux host
    Require Tool    cmake
    Require Tool    ninja
    Pub Get
    Flutter    0    build    linux    --debug    timeout=40min

Windows App
    ${os}=    Evaluate    platform.system()    modules=platform
    Skip If    '${os}' != 'Windows'    Windows builds need a Windows host
    Pub Get
    Flutter    0    build    windows    --debug    timeout=40min

*** Keywords ***
Require Android SDK
    Require Flutter
    ${sdk}=    Evaluate    os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or ''    modules=os
    Skip If    '${sdk}' == ''    no Android SDK (set ANDROID_HOME)

Require Xcode
    Require Flutter
    Require Tool    xcodebuild
    ${r}=    Run Process    xcodebuild    -version    stderr=STDOUT
    Skip If    ${r.rc} != 0    full Xcode is not installed

Merged Android Manifest
    ${files}=    Evaluate    [p for p in glob.glob($APP + '/build/app/intermediates/merged_manifest*/debug/**/AndroidManifest.xml', recursive=True)]    modules=glob
    Should Not Be Empty    ${files}
    ${m}=    Get File    ${files}[0]
    RETURN    ${m}
