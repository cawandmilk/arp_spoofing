TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
        arp_spoofing.cpp \
        main.cpp

HEADERS += \
    libnet/include/libnet/libnet-macros.h \
    libnet/include/libnet/libnet-headers.h \
    arp_spoofing.h
