import os
os.environ.setdefault("DB_DRIVER", "sqlite+aiosqlite")
os.environ.setdefault("DB_NAME", ":memory:")

import pytest


# ---------------------------------------------------------------------------
# ManifestAuditor tests
# ---------------------------------------------------------------------------


def test_manifest_auditor_allow_backup():
    from workers.mobile_worker.tools.manifest_auditor import ManifestAuditorTool
    tool = ManifestAuditorTool()
    manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.test.app">
        <application android:allowBackup="true" android:debuggable="false"/>
    </manifest>'''
    findings = tool._audit_manifest(manifest)
    titles = [f["title"] for f in findings]
    assert any("allowBackup" in t for t in titles)


def test_manifest_auditor_debuggable():
    from workers.mobile_worker.tools.manifest_auditor import ManifestAuditorTool
    tool = ManifestAuditorTool()
    manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.test.app">
        <application android:debuggable="true"/>
    </manifest>'''
    findings = tool._audit_manifest(manifest)
    severities = {f["title"]: f["severity"] for f in findings}
    assert any("debuggable" in t for t in severities)
    # debuggable should be critical
    for t, s in severities.items():
        if "debuggable" in t:
            assert s == "critical"


def test_manifest_auditor_cleartext_traffic():
    from workers.mobile_worker.tools.manifest_auditor import ManifestAuditorTool
    tool = ManifestAuditorTool()
    manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.test.app">
        <application android:usesCleartextTraffic="true"/>
    </manifest>'''
    findings = tool._audit_manifest(manifest)
    titles = [f["title"] for f in findings]
    assert any("cleartext" in t.lower() for t in titles)


def test_manifest_auditor_exported_components():
    from workers.mobile_worker.tools.manifest_auditor import ManifestAuditorTool
    tool = ManifestAuditorTool()
    manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.test.app">
        <application>
            <activity android:name=".MainActivity" android:exported="true"/>
            <service android:name=".MyService" android:exported="true"/>
            <receiver android:name=".MyReceiver" android:exported="true"/>
        </application>
    </manifest>'''
    findings = tool._audit_manifest(manifest)
    exported = tool._get_exported_components(manifest)
    assert len(exported) == 3


# ---------------------------------------------------------------------------
# IosPlistAuditor tests
# ---------------------------------------------------------------------------


def test_ios_plist_auditor_ats_exception():
    from workers.mobile_worker.tools.ios_plist_auditor import IosPlistAuditorTool
    tool = IosPlistAuditorTool()
    report = {
        "app_transport_security": {
            "NSAllowsArbitraryLoads": True,
        }
    }
    findings = tool._audit_plist(report)
    titles = [f["title"] for f in findings]
    assert any("NSAllowsArbitraryLoads" in t for t in titles)


def test_ios_plist_auditor_insecure_url_scheme():
    from workers.mobile_worker.tools.ios_plist_auditor import IosPlistAuditorTool
    tool = IosPlistAuditorTool()
    report = {
        "url_schemes": ["myapp", "fb12345"],
    }
    findings = tool._audit_plist(report)
    titles = [f["title"] for f in findings]
    assert any("URL scheme" in t for t in titles)


# ---------------------------------------------------------------------------
# DeeplinkAnalyzer tests
# ---------------------------------------------------------------------------


def test_deeplink_analyzer_android_intent_filters():
    from workers.mobile_worker.tools.deeplink_analyzer import DeeplinkAnalyzerTool
    tool = DeeplinkAnalyzerTool()
    manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.test.app">
        <application>
            <activity android:name=".DeepActivity">
                <intent-filter>
                    <action android:name="android.intent.action.VIEW"/>
                    <data android:scheme="myapp" android:host="login"/>
                </intent-filter>
            </activity>
        </application>
    </manifest>'''
    deeplinks = tool._parse_android_deeplinks(manifest)
    assert len(deeplinks) >= 1
    assert deeplinks[0]["scheme"] == "myapp"


def test_deeplink_analyzer_sensitive_path_detection():
    from workers.mobile_worker.tools.deeplink_analyzer import DeeplinkAnalyzerTool
    tool = DeeplinkAnalyzerTool()
    assert tool._is_sensitive_path("login") is True
    assert tool._is_sensitive_path("payment") is True
    assert tool._is_sensitive_path("account") is True
    assert tool._is_sensitive_path("about") is False
