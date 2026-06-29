# 定义时间记录函数
define time_wrapper
	@echo "开始时间: $$(date '+%Y-%m-%d %H:%M:%S.%3N')" && \
	start_time=$$(date +%s%3N) && \
	$(1) && \
	end_time=$$(date +%s%3N) && \
	duration=$$((end_time - start_time)) && \
	echo "结束时间: $$(date '+%Y-%m-%d %H:%M:%S.%3N')" && \
	echo "总计耗时: $$(echo "scale=3; $$duration/1000" | bc) 秒"
endef

.PHONY: xx
xx:
	$(call time_wrapper, \
		if [ -d "build" ]; then \
			cd build && cmake .. && $(MAKE); \
		else \
			mkdir build; \
			cd build && cmake ..; \
		fi)

%:
	$(call time_wrapper, \
		if [ -d "build" ]; then \
			cd build && cmake .. && +$(MAKE) $@; \
		else \
			mkdir build; \
			cd build && cmake ..; \
		fi)

clean:
	$(call time_wrapper, \
		if [ -d "build" ]; then \
			cd build && $(MAKE) clean && cd ..; \
			rm -rf build; \
		fi)

orm:
	$(call time_wrapper, bin/orm dbproxy/xml dbproxy/data)