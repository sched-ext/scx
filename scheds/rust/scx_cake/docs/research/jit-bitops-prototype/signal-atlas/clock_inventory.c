#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/timex.h>
#include <time.h>
#include <vulkan/vulkan.h>

/* Read-only clock queries. Creates a Vulkan device; submits no GPU work. */
static uint64_t now_ns(clockid_t id)
{
	struct timespec ts;
	if (clock_gettime(id, &ts)) {
		perror("clock_gettime");
		exit(1);
	}
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void check(VkResult result, const char *operation)
{
	if (result != VK_SUCCESS) {
		fprintf(stderr, "%s: VkResult %d\n", operation, result);
		exit(1);
	}
}

int main(void)
{
	VkApplicationInfo app = {
		.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
		.pApplicationName = "cake-clock-inventory",
		.apiVersion = VK_API_VERSION_1_1,
	};
	VkInstanceCreateInfo ici = {
		.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
		.pApplicationInfo = &app,
	};
	VkInstance instance;
	check(vkCreateInstance(&ici, NULL, &instance), "vkCreateInstance");
	uint32_t count = 0;
	check(vkEnumeratePhysicalDevices(instance, &count, NULL), "physical count");
	VkPhysicalDevice *physical = calloc(count, sizeof(*physical));
	if (!physical) return 1;
	check(vkEnumeratePhysicalDevices(instance, &count, physical), "physical list");
	VkPhysicalDevice gpu = VK_NULL_HANDLE;
	VkPhysicalDeviceProperties properties = {0};
	for (uint32_t i = 0; i < count; i++) {
		vkGetPhysicalDeviceProperties(physical[i], &properties);
		if (properties.vendorID == 0x10de) {
			gpu = physical[i];
			break;
		}
	}
	free(physical);
	if (gpu == VK_NULL_HANDLE) {
		fprintf(stderr, "No NVIDIA GPU found\n");
		return 1;
	}
	check(vkEnumerateDeviceExtensionProperties(gpu, NULL, &count, NULL), "extension count");
	VkExtensionProperties *extensions = calloc(count, sizeof(*extensions));
	if (!extensions) return 1;
	check(vkEnumerateDeviceExtensionProperties(gpu, NULL, &count, extensions), "extension list");
	int have_khr = 0, have_ext = 0;
	for (uint32_t i = 0; i < count; i++) {
		have_khr |= !strcmp(extensions[i].extensionName, "VK_KHR_calibrated_timestamps");
		have_ext |= !strcmp(extensions[i].extensionName, "VK_EXT_calibrated_timestamps");
	}
	free(extensions);
	if (!have_khr && !have_ext) {
		fprintf(stderr, "No calibrated timestamps extension\n");
		return 1;
	}
	const char *extension = have_khr ? "VK_KHR_calibrated_timestamps" : "VK_EXT_calibrated_timestamps";
	PFN_vkGetPhysicalDeviceCalibrateableTimeDomainsKHR domains_fn =
		(PFN_vkGetPhysicalDeviceCalibrateableTimeDomainsKHR)vkGetInstanceProcAddr(instance,
			have_khr ? "vkGetPhysicalDeviceCalibrateableTimeDomainsKHR" : "vkGetPhysicalDeviceCalibrateableTimeDomainsEXT");
	if (!domains_fn) return 1;
	check(domains_fn(gpu, &count, NULL), "time domain count");
	VkTimeDomainKHR *domains = calloc(count, sizeof(*domains));
	if (!domains) return 1;
	check(domains_fn(gpu, &count, domains), "time domain list");
	VkCalibratedTimestampInfoKHR *infos = calloc(count, sizeof(*infos));
	uint64_t *values = calloc(count, sizeof(*values));
	if (!infos || !values) return 1;
	uint32_t domain_count = 0;
	/* Present/swapchain domains require objects this observer does not create. */
	for (uint32_t i = 0; i < count; i++) {
		if (domains[i] != VK_TIME_DOMAIN_DEVICE_KHR &&
		    domains[i] != VK_TIME_DOMAIN_CLOCK_MONOTONIC_KHR &&
		    domains[i] != VK_TIME_DOMAIN_CLOCK_MONOTONIC_RAW_KHR)
			continue;
		infos[domain_count++] = (VkCalibratedTimestampInfoKHR){
			.sType = VK_STRUCTURE_TYPE_CALIBRATED_TIMESTAMP_INFO_KHR,
			.timeDomain = domains[i],
		};
	}
	if (!domain_count) return 1;
	vkGetPhysicalDeviceQueueFamilyProperties(gpu, &count, NULL);
	VkQueueFamilyProperties *queues = calloc(count, sizeof(*queues));
	if (!queues) return 1;
	vkGetPhysicalDeviceQueueFamilyProperties(gpu, &count, queues);
	uint32_t family = 0;
	while (family < count && !(queues[family].queueFlags & VK_QUEUE_GRAPHICS_BIT)) family++;
	if (family == count) return 1;
	uint32_t valid_bits = queues[family].timestampValidBits;
	free(queues);
	float priority = 0.5f;
	VkDeviceQueueCreateInfo qci = {
		.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
		.queueFamilyIndex = family, .queueCount = 1, .pQueuePriorities = &priority,
	};
	VkDeviceCreateInfo dci = {
		.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
		.queueCreateInfoCount = 1, .pQueueCreateInfos = &qci,
		.enabledExtensionCount = 1, .ppEnabledExtensionNames = &extension,
	};
	VkDevice device;
	check(vkCreateDevice(gpu, &dci, NULL, &device), "vkCreateDevice");
	PFN_vkGetCalibratedTimestampsKHR timestamps_fn =
		(PFN_vkGetCalibratedTimestampsKHR)vkGetDeviceProcAddr(device,
			have_khr ? "vkGetCalibratedTimestampsKHR" : "vkGetCalibratedTimestampsEXT");
	if (!timestamps_fn) return 1;
	struct timex tx = {0}; /* modes == 0 queries; never changes time. */
	int tx_state = adjtimex(&tx);
	printf("{\"extension\":\"%s\",\"vendor_id\":%u,\"device_id\":%u,", extension, properties.vendorID, properties.deviceID);
	printf("\"timestamp_period_ns\":%.9g,\"queue_timestamp_valid_bits\":%u,", properties.limits.timestampPeriod, valid_bits);
	printf("\"adjtimex\":{\"state\":%d,\"status\":%d,\"freq_scaled_ppm\":%ld,\"maxerror_us\":%ld,\"esterror_us\":%ld},", tx_state, tx.status, tx.freq, tx.maxerror, tx.esterror);
	struct timespec coarse;
	if (clock_getres(CLOCK_MONOTONIC_COARSE, &coarse)) return 1;
	printf("\"coarse_resolution_ns\":%" PRIu64 ",\"domains\":[", (uint64_t)coarse.tv_sec * UINT64_C(1000000000) + (uint64_t)coarse.tv_nsec);
	for (uint32_t i = 0; i < domain_count; i++) printf("%s%d", i ? "," : "", infos[i].timeDomain);
	printf("],\"samples\":[");
	for (unsigned i = 0; i < 16; i++) {
		uint64_t m0 = now_ns(CLOCK_MONOTONIC), raw = now_ns(CLOCK_MONOTONIC_RAW);
		uint64_t m1 = now_ns(CLOCK_MONOTONIC), dev = 0, before = now_ns(CLOCK_MONOTONIC);
		check(timestamps_fn(device, domain_count, infos, values, &dev), "calibrated timestamps");
		uint64_t after = now_ns(CLOCK_MONOTONIC);
		printf("%s{\"mono_before\":%" PRIu64 ",\"raw\":%" PRIu64 ",\"mono_after\":%" PRIu64 ",\"query_before\":%" PRIu64 ",\"query_after\":%" PRIu64 ",\"max_deviation_ns\":%" PRIu64 ",\"values\":[", i ? "," : "", m0, raw, m1, before, after, dev);
		for (uint32_t j = 0; j < domain_count; j++) printf("%s%" PRIu64, j ? "," : "", values[j]);
		printf("]}");
		if (i != 15) {
			struct timespec delay = {.tv_nsec = 250000000};
			while (nanosleep(&delay, &delay) && errno == EINTR) { }
		}
	}
	printf("]}\n");
	vkDestroyDevice(device, NULL);
	vkDestroyInstance(instance, NULL);
	free(values);
	free(infos);
	free(domains);
	return 0;
}
