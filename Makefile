SHELL := $(shell which bash)
OSS_ROOT ?= terark-downloads
DBG_FLAGS ?= -g3 -D_DEBUG
RLS_FLAGS ?= -O3 -DNDEBUG -g3
WITH_BMI2 ?= $(shell bash ./cpu_has_bmi2.sh)
ROCKSDB_SRC ?= ../rocksdb
TERARK_CORE_HOME ?= ../terark
VCPKG_HOME ?= /node-shared/vcpkg

ifeq "$(origin LD)" "default"
  LD := ${CXX}
endif

#COMPILER := $(shell ${CXX} --version | head -1 | awk '{split($$3, Ver, "."); printf("%s-%d.%d", $$1, Ver[1], Ver[2]);}')
# Makefile is stupid to parsing $(shell echo ')')
#COMPILER := $(shell ${CXX} --version | head -1 | sed 's/\(\S\+\)\s\+([^()]*)\s\+\([0-9]\+.[0-9]\+\).*/\1-\2/')
tmpfile := $(shell mktemp compiler-XXXXXX)
COMPILER := $(shell ${CXX} tools/configure/compiler.cpp -o ${tmpfile}.exe && ./${tmpfile}.exe && rm -f ${tmpfile}*)
#$(error COMPILER=${COMPILER})
UNAME_MachineSystem := $(shell uname -m -s | sed 's:[ /]:-:g')
TerarkLibDir ?= ${TERARK_CORE_HOME}/build/${UNAME_MachineSystem}-${COMPILER}-bmi2-${WITH_BMI2}/lib
BUILD_NAME := ${UNAME_MachineSystem}-${COMPILER}-bmi2-${WITH_BMI2}
BUILD_ROOT := build/${BUILD_NAME}
ddir:=${BUILD_ROOT}/dbg
rdir:=${BUILD_ROOT}/rls

gen_sh := $(dir $(lastword ${MAKEFILE_LIST}))gen_env_conf.sh

err := $(shell env bash ${gen_sh} "${CXX}" ${COMPILER} ${BUILD_ROOT}/env.mk; echo $$?)
ifneq "${err}" "0"
   $(error err = ${err} MAKEFILE_LIST = ${MAKEFILE_LIST}, PWD = ${PWD}, gen_sh = ${gen_sh} "${CXX}" ${COMPILER} ${BUILD_ROOT}/env.mk)
endif

TERARK_INC := -I${TERARK_CORE_HOME}/src -I$(TERARK_CORE_HOME)/3rdparty/zstd ${BOOST_INC}

include ${BUILD_ROOT}/env.mk

UNAME_System := $(shell uname | sed 's/^\([0-9a-zA-Z]*\).*/\1/')
ifeq (CYGWIN, ${UNAME_System})
  FPIC =
  # lazy expansion
  CYGWIN_LDFLAGS = -Wl,--out-implib=$@ \
				   -Wl,--export-all-symbols \
				   -Wl,--enable-auto-import
  DLL_SUFFIX = .dll.a
  CYG_DLL_FILE = $(shell echo $@ | sed 's:\(.*\)/lib\([^/]*\)\.a$$:\1/cyg\2:')
  COMMON_C_FLAGS  += -Wa,-mbig-obj
else
  ifeq (Darwin,${UNAME_System})
    DLL_SUFFIX = .dylib
  else
    DLL_SUFFIX = .so
  endif
  FPIC = -fPIC
  CYG_DLL_FILE = $@
endif
override CFLAGS += ${FPIC}
override CXXFLAGS += ${FPIC}
override LDFLAGS += ${FPIC}

ifeq "$(shell a=${COMPILER};echo $${a:0:3})" "g++"
  ifeq (Linux, ${UNAME_System})
    override LDFLAGS += -rdynamic
  endif
  ifeq (${UNAME_System},Darwin)
    COMMON_C_FLAGS += -Wa,-q
  endif
  override CXXFLAGS += -time
  ifeq "$(shell echo ${COMPILER} | awk -F- '{if ($$2 >= 4.8) print 1;}')" "1"
    CXX_STD := -std=gnu++17
  endif
endif

ifeq "${CXX_STD}" ""
  CXX_STD := -std=gnu++17
endif

# icc or icpc
ifeq "$(shell a=${COMPILER};echo $${a:0:2})" "ic"
  override CXXFLAGS += -xHost -fasm-blocks
  CPU = -xHost
else
  CPU = -march=native
  COMMON_C_FLAGS  += -Wno-deprecated-declarations
  ifeq "$(shell a=${COMPILER};echo $${a:0:5})" "clang"
    COMMON_C_FLAGS  += -fstrict-aliasing
  else
    COMMON_C_FLAGS  += -Wstrict-aliasing=3
  endif
endif

ifeq (${WITH_BMI2},1)
	CPU += -mbmi -mbmi2
else
	CPU += -mno-bmi -mno-bmi2
endif

COMMON_C_FLAGS  += -Wformat=2 -Wcomment
COMMON_C_FLAGS  += -Wall -Wextra
COMMON_C_FLAGS  += -Wno-unused-parameter
COMMON_C_FLAGS  += -D_GNU_SOURCE # For cygwin
COMMON_C_FLAGS  += -DROCKSDB_SUPPORT_THREAD_LOCAL

#-v #-Wall -Wparentheses
#COMMON_C_FLAGS  += ${COMMON_C_FLAGS} -Wpacked -Wpadded -v
#COMMON_C_FLAGS	 += ${COMMON_C_FLAGS} -Winvalid-pch
#COMMON_C_FLAGS  += ${COMMON_C_FLAGS} -fmem-report

ifeq "$(shell a=${COMPILER};echo $${a:0:5})" "clang"
  COMMON_C_FLAGS += -fcolor-diagnostics
endif

#CXXFLAGS +=
#CXXFLAGS += -fpermissive
#CXXFLAGS += -fexceptions
#CXXFLAGS += -fdump-translation-unit -fdump-class-hierarchy

override CFLAGS += ${COMMON_C_FLAGS}
override CXXFLAGS += ${COMMON_C_FLAGS}
#$(error ${CXXFLAGS} "----" ${COMMON_C_FLAGS})

DEFS := -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
DEFS += -DROCKSDB_PLATFORM_POSIX
ifeq (Darwin,${UNAME_System})
  DEFS += -DOS_MACOSX
endif
override CFLAGS   += ${DEFS}
override CXXFLAGS += ${DEFS}

override INCS := ${TERARK_INC} ${INCS}
override INCS += -I${ROCKSDB_SRC} -I${ROCKSDB_SRC}/include

#LIBS += -ldl
#LIBS += -lpthread

#extf = -pie
extf = -fno-stack-protector
#extf+=-fno-stack-protector-all
override CFLAGS += ${extf}
#override CFLAGS += -g3
override CXXFLAGS += ${extf}
#override CXXFLAGS += -g3
#CXXFLAGS += -fnothrow-opt

override INCS += -I/opt/include
override LIBS += -L/opt/lib -Wl,-Bstatic -Wl,-Bdynamic

ifeq (, ${prefix})
	ifeq (root, ${USER})
		prefix := /usr
	else
		prefix := /home/${USER}
	endif
endif
ToplingRocks_lib := topling-rocks
ToplingRocks_src := $(wildcard src/table/*.cc)
ToplingRocks_src += ${BUILD_ROOT}/git-version-cspp_memtab.cc

TerarkTests_src += $(wildcard src/table/tests/*.cc)

LIB_TERARK_D := -L${TerarkLibDir} -lterark-zbs-${COMPILER}-d -lterark-fsa-${COMPILER}-d -lterark-core-${COMPILER}-d
LIB_TERARK_R := -L${TerarkLibDir} -lterark-zbs-${COMPILER}-r -lterark-fsa-${COMPILER}-r -lterark-core-${COMPILER}-r

#function definition
#@param:${1} -- targets var prefix, such as bdb_util | core
#@param:${2} -- build type: d | r
objs = $(addprefix ${${2}dir}/, $(addsuffix .o, $(basename ${${1}_src})))

ToplingRocks_d_o := $(call objs,ToplingRocks,d)
ToplingRocks_r_o := $(call objs,ToplingRocks,r)
ToplingRocks_d := ${BUILD_ROOT}/lib/lib${ToplingRocks_lib}-${COMPILER}-d${DLL_SUFFIX}
ToplingRocks_r := ${BUILD_ROOT}/lib/lib${ToplingRocks_lib}-${COMPILER}-r${DLL_SUFFIX}
static_ToplingRocks_d := ${BUILD_ROOT}/lib/lib${ToplingRocks_lib}-${COMPILER}-d.a
static_ToplingRocks_r := ${BUILD_ROOT}/lib/lib${ToplingRocks_lib}-${COMPILER}-r.a

ALL_TARGETS = ToplingRocks
DBG_TARGETS = ${ToplingRocks_d}
RLS_TARGETS = ${ToplingRocks_r}

.PHONY : default all ToplingRocks

default : ToplingRocks
all : ${ALL_TARGETS}
ToplingRocks: ${ToplingRocks_d} \
				${ToplingRocks_r} \
				${static_ToplingRocks_d} \
				${static_ToplingRocks_r}

allsrc = ${ToplingRocks_src}
alldep = $(addprefix ${rdir}/, $(addsuffix .dep, $(basename ${allsrc}))) \
         $(addprefix ${ddir}/, $(addsuffix .dep, $(basename ${allsrc})))

.PHONY : dbg rls
dbg: ${DBG_TARGETS}
rls: ${RLS_TARGETS}

ifneq (${UNAME_System},Darwin)
${ToplingRocks_d} ${ToplingRocks_r} : LIBS += -lrt
endif

#${ToplingRocks_d} : override LIBS := ${LIB_TERARK_D} ${LIBS} -ltbb_debug
${ToplingRocks_d} : override LIBS := ${LIB_TERARK_D} ${LIBS} #-ltbb
${ToplingRocks_r} : override LIBS := ${LIB_TERARK_R} ${LIBS} #-ltbb

${ToplingRocks_d} ${ToplingRocks_r} : LIBS += -lpthread

${ToplingRocks_d} : $(call objs,ToplingRocks,d)
${ToplingRocks_r} : $(call objs,ToplingRocks,r)
${static_ToplingRocks_d} : $(call objs,ToplingRocks,d)
${static_ToplingRocks_r} : $(call objs,ToplingRocks,r)

TarBallBaseName := ${ToplingRocks_lib}-${BUILD_NAME}
TarBall := pkg/${ToplingRocks_lib}-${BUILD_NAME}
.PHONY : pkg
.PHONY : tgz
pkg : ${TarBall}
tgz : ${TarBall}.tgz

${TarBall}: ${ToplingRocks_d} ${static_ToplingRocks_d} \
            ${ToplingRocks_r} ${static_ToplingRocks_r} \
            $(wildcard ${TerarkLibDir}/libterark-*)
	rm -rf ${TarBall}
	mkdir -p ${TarBall}/lib
	mkdir -p ${TarBall}/bin
	mkdir -p ${TarBall}/include/table
ifeq (${PKG_WITH_DBG},1)
	cp -a ${BUILD_ROOT}/lib/lib${ToplingRocks_lib}-{${COMPILER}-,}d${DLL_SUFFIX} ${TarBall}/lib
	cp -a ${TerarkLibDir}/libterark-zbs-{${COMPILER}-,}d${DLL_SUFFIX} ${TarBall}/lib
	cp -a ${TerarkLibDir}/libterark-fsa-{${COMPILER}-,}d${DLL_SUFFIX} ${TarBall}/lib
	cp -a ${TerarkLibDir}/libterark-core-{${COMPILER}-,}d${DLL_SUFFIX} ${TarBall}/lib
  ifeq (${PKG_WITH_STATIC},1)
	mkdir -p ${TarBall}/lib_static
	cp -a ${BUILD_ROOT}/lib/lib${ToplingRocks_lib}-{${COMPILER}-,}d.a ${TarBall}/lib_static
	cp -a ${TerarkLibDir}/libterark-zbs-{${COMPILER}-,}d.a ${TarBall}/lib_static
	cp -a ${TerarkLibDir}/libterark-fsa-{${COMPILER}-,}d.a ${TarBall}/lib_static
	cp -a ${TerarkLibDir}/libterark-core-{${COMPILER}-,}d.a ${TarBall}/lib_static
  endif
endif
ifeq (${PKG_WITH_STATIC},1)
	mkdir -p ${TarBall}/lib_static
	cp -a ${BUILD_ROOT}/lib/lib${ToplingRocks_lib}-{${COMPILER}-,}r.a ${TarBall}/lib_static
	cp -a ${TerarkLibDir}/libterark-zbs-{${COMPILER}-,}r.a ${TarBall}/lib_static
	cp -a ${TerarkLibDir}/libterark-fsa-{${COMPILER}-,}r.a ${TarBall}/lib_static
	cp -a ${TerarkLibDir}/libterark-core-{${COMPILER}-,}r.a ${TarBall}/lib_static
endif
ifeq (${PKG_WITH_ROCKSDB},1)
	for header_dir in `find "../rocksdb/include" -type d`; do \
		install -d ${TarBall}/"$${header_dir#../rocksdb/}"; \
	done; \
	for header in `find "../rocksdb/include" -type f -name '*.h'`; do \
		install -C -m 644 $$header ${TarBall}/"$${header#../rocksdb/}"; \
	done
  ifeq (${PKG_WITH_STATIC},1)
	cp -a ../rocksdb/${UNAME_MachineSystem}-${COMPILER}/librocksdb.a* ${TarBall}/lib_static
  endif
	cp -a /usr/lib64/libzstd.so*                                       ${TarBall}/lib
	cp -a ../rocksdb/${UNAME_MachineSystem}-${COMPILER}/librocksdb.so* ${TarBall}/lib
	cp -a ../rocksdb/${UNAME_MachineSystem}-${COMPILER}/db_bench       ${TarBall}/bin
	cp -a ../rocksdb/${UNAME_MachineSystem}-${COMPILER}/ldb            ${TarBall}/bin
endif
	cp -a ${BUILD_ROOT}/lib/lib${ToplingRocks_lib}-{${COMPILER}-,}r${DLL_SUFFIX} ${TarBall}/lib
	cp -a ${TerarkLibDir}/libterark-zbs-{${COMPILER}-,}r${DLL_SUFFIX} ${TarBall}/lib
	cp -a ${TerarkLibDir}/libterark-fsa-{${COMPILER}-,}r${DLL_SUFFIX} ${TarBall}/lib
	cp -a ${TerarkLibDir}/libterark-core-{${COMPILER}-,}r${DLL_SUFFIX} ${TarBall}/lib
	cp src/table/terark_zip_table.h           ${TarBall}/include/table
	cp src/table/terark_zip_weak_function.h   ${TarBall}/include/table
	echo $(shell date "+%Y-%m-%d %H:%M:%S") > ${TarBall}/package.buildtime.txt
	echo $(shell git log | head -n1) >> ${TarBall}/package.buildtime.txt

${TarBall}.tgz: ${TarBall}
	cd pkg; tar czf ${TarBallBaseName}.tgz ${TarBallBaseName}

.PHONY: git-version.phony
${BUILD_ROOT}/git-version-%.cc: git-version.phony
	@mkdir -p $(dir $@)
	@rm -f $@.tmp
	@echo '__attribute__ ((visibility ("default"))) const char*' \
		  'git_version_hash_info_'$(patsubst git-version-%.cc,%,$(notdir $@))\
		  '() { return R"StrLiteral(git_version_hash_info_is:' > $@.tmp
	@env LC_ALL=C git log -n1 >> $@.tmp
	@env LC_ALL=C git diff >> $@.tmp
	@env LC_ALL=C $(CXX) --version >> $@.tmp
	@echo cpu_flag: $(CPU) >> $@.tmp
	@echo ')''StrLiteral";}' >> $@.tmp
	@#      ^^----- To prevent diff causing git-version compile fail
	@if test -f "$@" && cmp "$@" $@.tmp; then \
		rm $@.tmp; \
	else \
		mv $@.tmp $@; \
	fi

3rdparty/etcd-cpp-apiv3/build/src/libetcd-cpp-api.so:
	cd 3rdparty/etcd-cpp-apiv3; \
		mkdir -p build; \
		cd build; \
		cmake -DCMAKE_TOOLCHAIN_FILE=${VCPKG_HOME}/scripts/buildsystems/vcpkg.cmake ..
	+make -C 3rdparty/etcd-cpp-apiv3/build

%${DLL_SUFFIX}:
	@echo "----------------------------------------------------------------------------------"
	@echo "Creating dynamic library: $@"
	@echo BOOST_INC=${BOOST_INC} BOOST_SUFFIX=${BOOST_SUFFIX}
	@echo -e "OBJS:" $(addprefix "\n  ",$(sort $(filter %.o,$^)))
	@echo -e "LIBS:" $(addprefix "\n  ",${LIBS})
	@mkdir -p ${BUILD_ROOT}/lib
	@rm -f $@
	@rm -f $(subst -${COMPILER},, $@)
	@${LD} -shared $(sort $(filter %.o,$^)) ${LDFLAGS} ${LIBS} -o ${CYG_DLL_FILE} ${CYGWIN_LDFLAGS}
	cd ${BUILD_ROOT}/lib; ln -sf $(notdir $@) $(subst -${COMPILER},,$(notdir $@))
ifeq (CYGWIN, ${UNAME_System})
	@cp -l -f ${CYG_DLL_FILE} /usr/bin
endif

%.a:
	@echo "----------------------------------------------------------------------------------"
	@echo "Creating static library: $@"
	@echo BOOST_INC=${BOOST_INC} BOOST_SUFFIX=${BOOST_SUFFIX}
	@echo -e "OBJS:" $(addprefix "\n  ",$(sort $(filter %.o,$^)))
	@echo -e "LIBS:" $(addprefix "\n  ",${LIBS})
	@mkdir -p ${BUILD_ROOT}/lib
	@rm -f $@
	@rm -f $(subst -${COMPILER},, $@)
	@${AR} rcs $@ $(filter %.o,$^)
	cd ${BUILD_ROOT}/lib; ln -sf $(notdir $@) $(subst -${COMPILER},,$(notdir $@))

.PHONY : install
install : ToplingRocks
	cp lib/* ${prefix}/lib/

.PHONY : clean
clean:
	-rm -rf lib ${BUILD_ROOT} ${PRECOMPILED_HEADER_GCH}

.PHONY : test
test:


.PHONY : depends
depends : ${alldep}

ifneq ($(MAKECMDGOALS),cleanall)
ifneq ($(MAKECMDGOALS),clean)
-include ${alldep}
endif
endif

${ddir}/%.exe: ${ddir}/%.o
	@echo Linking ... $@
	${LD} ${LDFLAGS} -o $@ $< -L${BUILD_ROOT}/lib -L${TerarkLibDir}/lib -lterark-zbs-${COMPILER}-d -lterark-fsa-${COMPILER}-d -lterark-core-${COMPILER}-d ${LIBS}

${rdir}/%.exe: ${ddir}/%.o
	@echo Linking ... $@
	${LD} ${LDFLAGS} -o $@ $< -L${BUILD_ROOT}/lib -L${TerarkLibDir}/lib -lterark-zbs-${COMPILER}-r -lterark-fsa-${COMPILER}-r -lterark-core-${COMPILER}-r ${LIBS}

${ddir}/%.o: %.cpp
	@echo file: $< "->" $@
	@echo TERARK_INC=${TERARK_INC}
	@echo BOOST_INC=${BOOST_INC} BOOST_SUFFIX=${BOOST_SUFFIX}
	mkdir -p $(dir $@)
	${CXX} ${CXX_STD} ${CPU} -c ${DBG_FLAGS} ${CXXFLAGS} ${INCS} $< -o $@

${rdir}/%.o: %.cpp
	@echo file: $< "->" $@
	@echo TERARK_INC=${TERARK_INC}
	@echo BOOST_INC=${BOOST_INC} BOOST_SUFFIX=${BOOST_SUFFIX}
	mkdir -p $(dir $@)
	${CXX} ${CXX_STD} ${CPU} -c ${RLS_FLAGS} ${CXXFLAGS} ${INCS} $< -o $@

${ddir}/%.o: %.cc
	@echo file: $< "->" $@
	@echo TERARK_INC=${TERARK_INC}
	@echo BOOST_INC=${BOOST_INC} BOOST_SUFFIX=${BOOST_SUFFIX}
	mkdir -p $(dir $@)
	${CXX} ${CXX_STD} ${CPU} -c ${DBG_FLAGS} ${CXXFLAGS} ${INCS} $< -o $@

${rdir}/%.o: %.cc
	@echo file: $< "->" $@
	@echo TERARK_INC=${TERARK_INC}
	@echo BOOST_INC=${BOOST_INC} BOOST_SUFFIX=${BOOST_SUFFIX}
	mkdir -p $(dir $@)
	${CXX} ${CXX_STD} ${CPU} -c ${RLS_FLAGS} ${CXXFLAGS} ${INCS} $< -o $@

${ddir}/%.o : %.c
	@echo file: $< "->" $@
	mkdir -p $(dir $@)
	${CC} -c ${CPU} ${DBG_FLAGS} ${CFLAGS} ${INCS} $< -o $@

${rdir}/%.o : %.c
	@echo file: $< "->" $@
	mkdir -p $(dir $@)
	${CC} -c ${CPU} ${RLS_FLAGS} ${CFLAGS} ${INCS} $< -o $@

${ddir}/%.s : %.cpp ${PRECOMPILED_HEADER_GCH}
	@echo file: $< "->" $@
	${CXX} -S ${CPU} ${DBG_FLAGS} ${CXXFLAGS} ${INCS} $< -o $@

${rdir}/%.s : %.cpp ${PRECOMPILED_HEADER_GCH}
	@echo file: $< "->" $@
	${CXX} -S ${CPU} ${RLS_FLAGS} ${CXXFLAGS} ${INCS} $< -o $@

${ddir}/%.s : %.c ${PRECOMPILED_HEADER_GCH}
	@echo file: $< "->" $@
	${CC} -S ${CPU} ${DBG_FLAGS} ${CXXFLAGS} ${INCS} $< -o $@

${rdir}/%.s : %.c ${PRECOMPILED_HEADER_GCH}
	@echo file: $< "->" $@
	${CC} -S ${CPU} ${RLS_FLAGS} ${CXXFLAGS} ${INCS} $< -o $@

${rdir}/%.dep : %.c
	@echo file: $< "->" $@
	@echo INCS = ${INCS}
	mkdir -p $(dir $@)
	${CC} -M -MT $(basename $@).o ${INCS} $< > $@

${ddir}/%.dep : %.c
	@echo file: $< "->" $@
	@echo INCS = ${INCS}
	mkdir -p $(dir $@)
	${CC} -M -MT $(basename $@).o ${INCS} $< > $@

${rdir}/%.dep : %.cpp
	@echo file: $< "->" $@
	@echo INCS = ${INCS}
	mkdir -p $(dir $@)
	${CXX} ${CXX_STD} -M -MT $(basename $@).o ${INCS} $< > $@

${ddir}/%.dep : %.cpp
	@echo file: $< "->" $@
	@echo INCS = ${INCS}
	mkdir -p $(dir $@)
	${CXX} ${CXX_STD} -M -MT $(basename $@).o ${INCS} $< > $@

