CURRENT_PATH := $(shell pwd)
DIRS := $(shell find $(CURRENT_PATH) -maxdepth 1 -type d)
BASE_DIRS := $(basename $(patsubst $(CURRENT_PATH)/%, %, $(DIRS)))
BASE_DIRS := $(filter-out $(CURRENT_PATH), $(BASE_DIRS))

ifeq ($(ENHANCED_KERNEL), enhanced)
all:
	@for dir in ${BASE_DIRS}; do 	\
		make -C $(CURRENT_PATH)/$$dir;	\
		if [ -f $(CURRENT_PATH)/$$dir/*.ko ];then	\
			cp $(CURRENT_PATH)/$$dir/*.ko ../ko ||exit;	\
		fi	\
	done

install:
	@for dir in ${BASE_DIRS}; do 	\
		make -C $(CURRENT_PATH)/$$dir install ||exit; done

uninstall:
	@for dir in ${BASE_DIRS}; do 	\
		make -C $(CURRENT_PATH)/$$dir uninstall ||exit; done

clean:
	@for dir in ${BASE_DIRS}; do 	\
		make -C $(CURRENT_PATH)/$$dir clean > /dev/null 2>&1||exit; done
	@rm -rf ../ko/*
else
all:

install:

uninstall:

clean:

endif
