/*
 * Copyright (C) 2011 ~ 2019 Deepin Technology Co., Ltd.
 *
 * Author:     zorowk <near.kingzero@gmail.com>
 *
 * Maintainer: zorowk <near.kingzero@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef AUTHAGENT_H
#define AUTHAGENT_H

#include <security/pam_appl.h>
#include <QObject>

#define MAX_VERIFY_FAILED 5

class DeepinAuthFramework;
class AuthAgent : public QObject {
    Q_OBJECT
public:
    enum AuthFlag {
        Password = 1 << 0,
        Fingerprint = 1 << 1,
        Face = 1 << 2,
        ActiveDirectory = 1 << 3
    };

    enum FingerprintStatus {
        MATCH = 0,
        NO_MATCH,
        ERROR,
        RETRY,
        DISCONNECTED
    };

    enum FpRetryStatus {
        SWIPE_TOO_SHORT = 1,
        FINGER_NOT_CENTERED,
        REMOVE_AND_RETRY
    };

    explicit AuthAgent(const QString& user_name, AuthFlag type, DeepinAuthFramework *deepin);
    ~AuthAgent();

    QString UserName() const;
    void Authenticate();
    void Cancel();
    DeepinAuthFramework *deepinAuth() { return m_deepinauth; }

private:
    QString PamService(AuthFlag type) const;
    void pamFingerprintMessage(const QString& message);
    static int funConversation(int num,
                               const struct pam_message** msg,
                               struct pam_response** resp,
                               void* app_data);

private:
    DeepinAuthFramework* m_deepinauth = nullptr;
    pam_handle_t* m_pamHandle = nullptr;
    int  m_lastStatus = 255;
    int  m_verifyFailed = MAX_VERIFY_FAILED;

    AuthFlag m_type = Password;
    QString m_username;
    QString m_password;
};

#endif // AUTHAGENT_H
