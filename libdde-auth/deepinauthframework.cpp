#include "deepinauthframework.h"
#include "interface/deepinauthinterface.h"

#include <QTimer>
#include <QVariant>
#include <QThread>

static QString USERNAME;
static QString PASSWORD;

DeepinAuthFramework::DeepinAuthFramework(DeepinAuthInterface *inter, QObject *parent)
    : QObject(parent)
    , m_interface(inter)
{
    m_authThread = new QThread;
    m_authThread->start();
}

DeepinAuthFramework::~DeepinAuthFramework()
{
    if(m_authThread != nullptr) {
        if(m_authThread->isRunning()) m_authThread->quit();
        m_authThread->deleteLater();
    }
}

void DeepinAuthFramework::SetUser(const QString &username)
{
    USERNAME = username;
}

void DeepinAuthFramework::Authenticate()
{
    if (m_authagent == nullptr) {
        m_authagent = new AuthAgent(USERNAME, AuthAgent::Password, this);
        m_authagent->moveToThread(m_authThread);
        if(!m_authThread->isRunning()) m_authThread->start();

        // It takes time to auth again after cancel!
        QTimer::singleShot(100, m_authagent, [=] {
            if (!PASSWORD.isEmpty()) {
                m_authagent->Authenticate();
            }
        });
    }
}

void DeepinAuthFramework::Clear()
{
    if (!m_authagent.isNull()) {
        delete m_authagent;
        m_authagent = nullptr;
    }

    PASSWORD.clear();
}

void DeepinAuthFramework::setPassword(const QString &password)
{
    PASSWORD = password;
}

const QString DeepinAuthFramework::RequestEchoOff(const QString &msg)
{
    Q_UNUSED(msg);

    return PASSWORD;
}

const QString DeepinAuthFramework::RequestEchoOn(const QString &msg)
{
    return msg;
}

void DeepinAuthFramework::DisplayErrorMsg(AuthAgent::AuthFlag type, const QString &msg)
{
    m_interface->onDisplayErrorMsg(type, msg);
}

void DeepinAuthFramework::DisplayTextInfo(AuthAgent::AuthFlag type, const QString &msg)
{
    m_interface->onDisplayTextInfo(type, msg);
}

void DeepinAuthFramework::RespondResult(AuthAgent::AuthFlag type, const QString &msg)
{
    m_interface->onPasswordResult(type, msg);
}
