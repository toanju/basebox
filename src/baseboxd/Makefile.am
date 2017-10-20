MAINTAINERCLEANFILES = Makefile.in

SUBDIRS = 

sbin_PROGRAMS = baseboxd

AM_CPPFLAGS = -I$(top_srcdir)/src
AM_LDFLAGS = 

PROTO_FILES = \
	grpc/proto/ietf-interfaces.proto \
	grpc/proto/openconfig-interfaces.proto

PROTO_SOURCES = \
	ietf-interfaces.pb.cc \
	ietf-interfaces.pb.h \
	openconfig-interfaces.pb.cc \
	openconfig-interfaces.pb.h

#GRPC_SOURCES = todo

#openconfig-interfaces.proto ietf-interfaces.proto
BUILT_SOURCES = \
	$(PROTO_SOURCES)

CLEANFILES = \
	$(PROTO_SOURCES)

nodist_baseboxd_SOURCES = \
	$(PROTO_SOURCES)

baseboxd_SOURCES = \
	baseboxd.cpp
	
baseboxd_LDADD = -lpthread \
		 -lrt \
		 ../roflibs/libroflibs.la

PROTOC=/usr/bin/protoc
GRPC_CPP_PLUGIN_PATH=/usr/bin/grpc_cpp_plugin
PROTOS_PATH=./grpc/proto

$(GRPC_SOURCES):
	$(PROTOC) -I $(PROTOS_PATH) --grpc_out=. --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN_PATH) $^

# can be optimized though since protoc is called #PROTO_SOURCES times:
$(PROTO_SOURCES): $(PROTO_FILES)
	$(PROTOC) -I $(PROTOS_PATH) --cpp_out=. $^
