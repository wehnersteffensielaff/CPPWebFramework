#-------------------------------------------------
#
# Project created by QtCreator 2015-07-20T11:14:10
#
#-------------------------------------------------

QT       += core network xml

TARGET = Sessions
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp \    
    model/user.cpp \
    controllers/indexcontroller.cpp \
    controllers/logincontroller.cpp

HEADERS += \    
    model/user.h \
    controllers/indexcontroller.h \
    controllers/logincontroller.h

QMAKE_CXXFLAGS += -std=c++11

OTHER_FILES += \
    server/config/CPPWeb.ini \
    server/config/log/CPPWebServer.log

DISTFILES += \
    server/pages/index.xhtml \
    server/pages/login.xhtml \
    server/pages/index.xhtml \
    server/pages/login.xhtml \
    server/pages/index.view \
    server/pages/login.view



unix {
    INCLUDEPATH += /usr/lib
    debug {
        LIBS += -L/usr/lib -lCPPWebFrameworkd
    }
    release {
        LIBS += -L/usr/lib -lCPPWebFramework
    }
}

macx {
    INCLUDEPATH += /usr/local/lib
    debug {
        LIBS += -L/usr/local/lib -lCPPWebFrameworkd
    }
    release {
        LIBS += -L/usr/local/lib -lCPPWebFramework
    }
}

win32 {
    INCLUDEPATH += C:/
    debug {
        LIBS += -LC:/cwf -lCPPWebFrameworkd
    }
    release {
        LIBS += -LC:/cwf -lCPPWebFramework
    }
}

CONFIG(release, debug|release) {
    QMAKE_CXXFLAGS_RELEASE -= -O1
    QMAKE_CXXFLAGS_RELEASE -= -O2
    QMAKE_CXXFLAGS_RELEASE += -O3
}

#Strongly recommended
#LIBS += -ljemalloc
