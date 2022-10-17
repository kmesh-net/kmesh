CURRENT_PATH := $(shell pwd)
DIRS := $(shell find $(CURRENT_PATH) -maxdepth 1 -type d)
BASE_DIRS := $(basename $(patsubst $(CURRENT_PATH)/%, %, $(DIRS)))
BASE_DIRS := $(filter-out $(CURRENT_PATH), $(BASE_DIRS))


all:
	@for dir in ${BASE_DIRS}; do 	\
		make -C $(CURRENT_PATH)/$$dir > /dev/null 2>&1;	\
		if [ -f $(CURRENT_PATH)/$$dir/*.ko ];then	\
			cp $(CURRENT_PATH)/$$dir/*.ko ../ko ||exit;	\
		fi	\
	done
clean:
	@for dir in ${BASE_DIRS}; do 	\
		make -C $(CURRENT_PATH)/$$dir clean > /dev/null 2>&1||exit; done
	@rm -rf ../ko/*
