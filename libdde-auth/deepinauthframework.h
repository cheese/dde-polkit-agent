#ifndef DEEPINAUTHFRAMEWORK_H
#define DEEPINAUTHFRAMEWORK_H

#include "authagent.h"

#include <QObject>
#include <QPointer>

class DeepinAuthInterface;
class QThread;
class DeepinAuthFramework : public QObject
{
    Q_OBJECT
public:
    explicit DeepinAuthFramework(DeepinAuthInterface *inter, QObject *parent = nullptr);
    ~DeepinAuthFramework();

    friend class AuthAgent;

public slots:
    void SetUser(const QString &username);
    void Authenticate();
    void Clear();
    void setPassword(const QString &password);

private:
    const QString RequestEchoOff(const QString &msg);
    const QString RequestEchoOn(const QString &msg);
    void DisplayErrorMsg(AuthAgent::AuthFlag type, const QString &msg);
    void DisplayTextInfo(AuthAgent::AuthFlag type, const QString &msg);
    void RespondResult(AuthAgent::AuthFlag type, const QString &msg);

private:
    DeepinAuthInterface *m_interface;
    QPointer<AuthAgent> m_authagent;
    QThread* m_authThread = nullptr;
};

#endif // DEEPINAUTHFRAMEWORK_H
