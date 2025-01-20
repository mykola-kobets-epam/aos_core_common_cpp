/*
 * Copyright (C) 2025 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fstream>

#include "ocispec/ocispec.hpp"

#include "utils/exception.hpp"
#include "utils/json.hpp"
#include "utils/time.hpp"

namespace aos::common::oci {

/***********************************************************************************************************************
 * Static
 **********************************************************************************************************************/

namespace {

std::string ToStdString(const String& str)
{
    return str.CStr();
}

void CapabilitiesFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::LinuxCapabilities& capabilities)
{
    if (object.Has("bounding")) {
        for (const auto& cap : utils::GetArrayValue<std::string>(object, "bounding")) {
            auto err = capabilities.mBounding.EmplaceBack(cap.c_str());
            AOS_ERROR_CHECK_AND_THROW("bounding capabilities parsing error", err);
        }
    }

    if (object.Has("effective")) {
        for (const auto& cap : utils::GetArrayValue<std::string>(object, "effective")) {
            auto err = capabilities.mEffective.EmplaceBack(cap.c_str());
            AOS_ERROR_CHECK_AND_THROW("effective capabilities parsing error", err);
        }
    }

    if (object.Has("inheritable")) {
        for (const auto& cap : utils::GetArrayValue<std::string>(object, "inheritable")) {
            auto err = capabilities.mInheritable.EmplaceBack(cap.c_str());
            AOS_ERROR_CHECK_AND_THROW("inheritable capabilities parsing error", err);
        }
    }

    if (object.Has("permitted")) {
        for (const auto& cap : utils::GetArrayValue<std::string>(object, "permitted")) {
            auto err = capabilities.mPermitted.EmplaceBack(cap.c_str());
            AOS_ERROR_CHECK_AND_THROW("permitted capabilities parsing error", err);
        }
    }

    if (object.Has("ambient")) {
        for (const auto& cap : utils::GetArrayValue<std::string>(object, "ambient")) {
            auto err = capabilities.mAmbient.EmplaceBack(cap.c_str());
            AOS_ERROR_CHECK_AND_THROW("ambient capabilities parsing error", err);
        }
    }
}

Poco::JSON::Object CapabilitiesToJSON(const aos::oci::LinuxCapabilities& capabilities)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    if (!capabilities.mBounding.IsEmpty()) {
        object.set("bounding", utils::ToJsonArray(capabilities.mBounding, ToStdString));
    }

    if (!capabilities.mEffective.IsEmpty()) {
        object.set("effective", utils::ToJsonArray(capabilities.mEffective, ToStdString));
    }

    if (!capabilities.mInheritable.IsEmpty()) {
        object.set("inheritable", utils::ToJsonArray(capabilities.mInheritable, ToStdString));
    }

    if (!capabilities.mPermitted.IsEmpty()) {
        object.set("permitted", utils::ToJsonArray(capabilities.mPermitted, ToStdString));
    }

    if (!capabilities.mAmbient.IsEmpty()) {
        object.set("ambient", utils::ToJsonArray(capabilities.mAmbient, ToStdString));
    }

    return object;
}

void POSIXRlimitFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::POSIXRlimit& rlimit)
{
    const auto type = object.GetValue<std::string>("type");

    rlimit.mType = type.c_str();
    rlimit.mHard = object.GetValue<uint64_t>("hard");
    rlimit.mSoft = object.GetValue<uint64_t>("soft");
}

Poco::JSON::Object POSIXRlimitToJSON(const aos::oci::POSIXRlimit& rlimit)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    object.set("type", rlimit.mType.CStr());
    object.set("hard", rlimit.mHard);
    object.set("soft", rlimit.mSoft);

    return object;
}

void UserFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::User& user)
{
    user.mUID = object.GetValue<uint32_t>("uid");
    user.mGID = object.GetValue<uint32_t>("gid");

    if (const auto umask = object.GetOptionalValue<uint32_t>("umask"); umask.has_value()) {
        user.mUmask.SetValue(*umask);
    }

    for (const auto gid : utils::GetArrayValue<uint32_t>(object, "additionalGids")) {
        auto err = user.mAdditionalGIDs.EmplaceBack(gid);
        AOS_ERROR_CHECK_AND_THROW("additionalGids parsing error", err);
    }

    const auto username = object.GetValue<std::string>("username");
    user.mUsername      = username.c_str();
}

Poco::JSON::Object UserToJSON(const aos::oci::User& user)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    object.set("uid", user.mUID);
    object.set("gid", user.mGID);

    if (user.mUmask.HasValue() && *user.mUmask > 0) {
        object.set("umask", *user.mUmask);
    }

    if (!user.mAdditionalGIDs.IsEmpty()) {
        object.set("additionalGids", utils::ToJsonArray(user.mAdditionalGIDs, [](const auto& gid) { return gid; }));
    }

    if (!user.mUsername.IsEmpty()) {
        object.set("username", user.mUsername.CStr());
    }

    return object;
}

void ProcessFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::Process& process)
{
    process.mTerminal        = object.GetValue<bool>("terminal");
    process.mNoNewPrivileges = object.GetValue<bool>("noNewPrivileges");

    if (object.Has("user")) {
        UserFromJSON(object.GetObject("user"), process.mUser);
    }

    if (object.Has("args")) {
        for (const auto& arg : utils::GetArrayValue<std::string>(object, "args")) {
            auto err = process.mArgs.EmplaceBack(arg.c_str());
            AOS_ERROR_CHECK_AND_THROW("args parsing error", err);
        }
    }

    if (object.Has("env")) {
        for (const auto& env : utils::GetArrayValue<std::string>(object, "env")) {
            auto err = process.mEnv.EmplaceBack(env.c_str());
            AOS_ERROR_CHECK_AND_THROW("env parsing error", err);
        }
    }

    const auto cwd = object.GetValue<std::string>("cwd");
    process.mCwd   = cwd.c_str();

    if (object.Has("capabilities")) {
        auto capabilities = std::make_unique<aos::oci::LinuxCapabilities>();

        CapabilitiesFromJSON(object.GetObject("capabilities"), *capabilities);

        process.mCapabilities.SetValue(*capabilities);
    }

    if (object.Has("rlimits")) {
        auto rlimits = utils::GetArrayValue<aos::oci::POSIXRlimit>(object, "rlimits", [](const auto& value) {
            aos::oci::POSIXRlimit rlimit;

            POSIXRlimitFromJSON(utils::CaseInsensitiveObjectWrapper(value), rlimit);

            return rlimit;
        });

        for (const auto& rlimit : rlimits) {
            auto err = process.mRlimits.EmplaceBack(rlimit);
            AOS_ERROR_CHECK_AND_THROW("rlimits parsing error", err);
        }
    }
}

Poco::JSON::Object ProcessToJSON(const aos::oci::Process& process)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    object.set("terminal", process.mTerminal);
    object.set("user", UserToJSON(process.mUser));

    if (!process.mArgs.IsEmpty()) {
        object.set("args", utils::ToJsonArray(process.mArgs, ToStdString));
    }

    if (!process.mEnv.IsEmpty()) {
        object.set("env", utils::ToJsonArray(process.mEnv, ToStdString));
    }

    object.set("cwd", process.mCwd.CStr());

    if (process.mCapabilities.HasValue()) {
        if (auto capabilities = CapabilitiesToJSON(process.mCapabilities.GetValue()); capabilities.size() > 0) {
            object.set("capabilities", capabilities);
        }
    }

    if (!process.mRlimits.IsEmpty()) {
        object.set("rlimits", utils::ToJsonArray(process.mRlimits, POSIXRlimitToJSON));
    }

    object.set("noNewPrivileges", process.mNoNewPrivileges);

    return object;
}

void RootFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::Root& root)
{
    const auto path = object.GetValue<std::string>("path");

    root.mPath     = path.c_str();
    root.mReadonly = object.GetValue<bool>("readonly");
}

Poco::JSON::Object RootToJSON(const aos::oci::Root& root)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    object.set("path", root.mPath.CStr());
    object.set("readonly", root.mReadonly);

    return object;
}

void MountFromJSON(const utils::CaseInsensitiveObjectWrapper& object, Mount& mount)
{

    const auto destination = object.GetValue<std::string>("destination");
    const auto type        = object.GetValue<std::string>("type");
    const auto source      = object.GetValue<std::string>("source");

    mount.mDestination = destination.c_str();
    mount.mType        = type.c_str();
    mount.mSource      = source.c_str();

    for (const auto& option : utils::GetArrayValue<std::string>(object, "options")) {
        auto err = mount.mOptions.EmplaceBack(option.c_str());
        AOS_ERROR_CHECK_AND_THROW("mount options parsing error", err);
    }
}

Poco::JSON::Object MountToJSON(const Mount& mount)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    object.set("destination", mount.mDestination.CStr());

    if (!mount.mType.IsEmpty()) {
        object.set("type", mount.mType.CStr());
    }

    if (!mount.mSource.IsEmpty()) {
        object.set("source", mount.mSource.CStr());
    }

    if (!mount.mOptions.IsEmpty()) {
        object.set("options", utils::ToJsonArray(mount.mOptions, ToStdString));
    }

    return object;
}

void DeviceCgroupFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::LinuxDeviceCgroup& device)
{
    const auto allow  = object.GetValue<bool>("allow");
    const auto type   = object.GetValue<std::string>("type");
    const auto access = object.GetValue<std::string>("access");

    device.mType   = type.c_str();
    device.mAccess = access.c_str();
    device.mAllow  = allow;

    if (const auto major = object.GetOptionalValue<int64_t>("major"); major.has_value()) {
        device.mMajor.SetValue(*major);
    }

    if (const auto minor = object.GetOptionalValue<int64_t>("minor"); minor.has_value()) {
        device.mMinor.SetValue(*minor);
    }
}

Poco::JSON::Object DeviceCgroupToJSON(const aos::oci::LinuxDeviceCgroup& device)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    object.set("allow", device.mAllow);

    if (!device.mType.IsEmpty()) {
        object.set("type", device.mType.CStr());
    }

    if (device.mMajor.HasValue()) {
        object.set("major", device.mMajor.GetValue());
    }

    if (device.mMinor.HasValue()) {
        object.set("minor", device.mMinor.GetValue());
    }

    if (!device.mAccess.IsEmpty()) {
        object.set("access", device.mAccess.CStr());
    }

    return object;
}

void LinuxMemoryFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::LinuxMemory& memory)
{
    if (const auto limit = object.GetOptionalValue<int64_t>("limit"); limit.has_value()) {
        memory.mLimit.SetValue(*limit);
    }

    if (const auto reservation = object.GetOptionalValue<int64_t>("reservation"); reservation.has_value()) {
        memory.mReservation.SetValue(*reservation);
    }

    if (const auto swap = object.GetOptionalValue<int64_t>("swap"); swap.has_value()) {
        memory.mSwap.SetValue(*swap);
    }

    if (const auto kernel = object.GetOptionalValue<int64_t>("kernel"); kernel.has_value()) {
        memory.mKernel.SetValue(*kernel);
    }

    if (const auto kernelTCP = object.GetOptionalValue<int64_t>("kernelTCP"); kernelTCP.has_value()) {
        memory.mKernelTCP.SetValue(*kernelTCP);
    }

    if (const auto swappiness = object.GetOptionalValue<uint64_t>("swappiness"); swappiness.has_value()) {
        memory.mSwappiness.SetValue(*swappiness);
    }

    if (const auto disableOOMKiller = object.GetOptionalValue<bool>("disableOOMKiller"); disableOOMKiller.has_value()) {
        memory.mDisableOOMKiller.SetValue(*disableOOMKiller);
    }

    if (const auto useHierarchy = object.GetOptionalValue<bool>("useHierarchy"); useHierarchy.has_value()) {
        memory.mUseHierarchy.SetValue(*useHierarchy);
    }

    if (const auto checkBeforeUpdate = object.GetOptionalValue<bool>("checkBeforeUpdate");
        checkBeforeUpdate.has_value()) {
        memory.mCheckBeforeUpdate.SetValue(*checkBeforeUpdate);
    }
}

Poco::JSON::Object LinuxMemoryToJSON(const aos::oci::LinuxMemory& lnxMemory)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    if (lnxMemory.mLimit.HasValue()) {
        object.set("limit", lnxMemory.mLimit.GetValue());
    }

    if (lnxMemory.mReservation.HasValue()) {
        object.set("reservation", lnxMemory.mReservation.GetValue());
    }

    if (lnxMemory.mSwap.HasValue()) {
        object.set("swap", lnxMemory.mSwap.GetValue());
    }

    if (lnxMemory.mKernel.HasValue()) {
        object.set("kernel", lnxMemory.mKernel.GetValue());
    }

    if (lnxMemory.mKernelTCP.HasValue()) {
        object.set("kernelTCP", lnxMemory.mKernelTCP.GetValue());
    }

    if (lnxMemory.mSwappiness.HasValue()) {
        object.set("swappiness", lnxMemory.mSwappiness.GetValue());
    }

    if (lnxMemory.mDisableOOMKiller.HasValue()) {
        object.set("disableOOMKiller", lnxMemory.mDisableOOMKiller.GetValue());
    }

    if (lnxMemory.mUseHierarchy.HasValue()) {
        object.set("useHierarchy", lnxMemory.mUseHierarchy.GetValue());
    }

    if (lnxMemory.mCheckBeforeUpdate.HasValue()) {
        object.set("checkBeforeUpdate", lnxMemory.mCheckBeforeUpdate.GetValue());
    }

    return object;
}

void LinuxCPUFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::LinuxCPU& cpu)
{
    if (const auto shares = object.GetOptionalValue<uint64_t>("shares"); shares.has_value()) {
        cpu.mShares.SetValue(*shares);
    }

    if (const auto quota = object.GetOptionalValue<int64_t>("quota"); quota.has_value()) {
        cpu.mQuota.SetValue(*quota);
    }

    if (const auto burst = object.GetOptionalValue<uint64_t>("burst"); burst.has_value()) {
        cpu.mBurst.SetValue(*burst);
    }

    if (const auto period = object.GetOptionalValue<uint64_t>("period"); period.has_value()) {
        cpu.mPeriod.SetValue(*period);
    }

    if (const auto realtimeRuntime = object.GetOptionalValue<int64_t>("realtimeRuntime"); realtimeRuntime.has_value()) {
        cpu.mRealtimeRuntime.SetValue(*realtimeRuntime);
    }

    if (const auto realtimePeriod = object.GetOptionalValue<uint64_t>("realtimePeriod"); realtimePeriod.has_value()) {
        cpu.mRealtimePeriod.SetValue(*realtimePeriod);
    }

    if (const auto cpus = object.GetOptionalValue<std::string>("cpus"); cpus.has_value()) {
        cpu.mCpus.SetValue(cpus->c_str());
    }

    if (const auto mems = object.GetOptionalValue<std::string>("mems"); mems.has_value()) {
        cpu.mMems.SetValue(mems->c_str());
    }

    if (const auto idle = object.GetOptionalValue<int64_t>("idle"); idle.has_value()) {
        cpu.mIdle.SetValue(*idle);
    }
}

Poco::JSON::Object LinuxCPUToJSON(const aos::oci::LinuxCPU& cpu)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    if (cpu.mShares.HasValue()) {
        object.set("shares", cpu.mShares.GetValue());
    }

    if (cpu.mQuota.HasValue()) {
        object.set("quota", cpu.mQuota.GetValue());
    }

    if (cpu.mBurst.HasValue()) {
        object.set("burst", cpu.mBurst.GetValue());
    }

    if (cpu.mPeriod.HasValue()) {
        object.set("period", cpu.mPeriod.GetValue());
    }

    if (cpu.mRealtimeRuntime.HasValue()) {
        object.set("realtimeRuntime", cpu.mRealtimeRuntime.GetValue());
    }

    if (cpu.mRealtimePeriod.HasValue()) {
        object.set("realtimePeriod", cpu.mRealtimePeriod.GetValue());
    }

    if (cpu.mCpus.HasValue()) {
        object.set("cpus", cpu.mCpus.GetValue().CStr());
    }

    if (cpu.mMems.HasValue()) {
        object.set("mems", cpu.mMems.GetValue().CStr());
    }

    if (cpu.mIdle.HasValue()) {
        object.set("idle", cpu.mIdle.GetValue());
    }

    return object;
}

void LinuxPidsFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::LinuxPids& pids)
{
    pids.mLimit = object.GetValue<int64_t>("limit");
}

Poco::JSON::Object LinuxPidsToJSON(const aos::oci::LinuxPids& pids)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    object.set("limit", pids.mLimit);

    return object;
}

void SysctlFromJSON(const Poco::Dynamic::Var& var, decltype(aos::oci::Linux::mSysctl)& sysctl)
{
    auto object = var.extract<Poco::JSON::Object::Ptr>();

    for (const auto& [key, value] : *object) {
        const auto valueStr = value.convert<std::string>();

        auto err = sysctl.TryEmplace(key.c_str(), valueStr.c_str());
        AOS_ERROR_CHECK_AND_THROW("sysctl parsing error", err);
    }
}

Poco::JSON::Object SysctlToJSON(const decltype(aos::oci::Linux::mSysctl)& sysctl)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    for (const auto& [key, value] : sysctl) {
        object.set(key.CStr(), value.CStr());
    }

    return object;
}

void LinuxResourcesFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::LinuxResources& resources)
{
    auto devices = utils::GetArrayValue<aos::oci::LinuxDeviceCgroup>(object, "devices", [](const auto& value) {
        aos::oci::LinuxDeviceCgroup device;

        DeviceCgroupFromJSON(utils::CaseInsensitiveObjectWrapper(value), device);

        return device;
    });

    for (const auto& device : devices) {
        auto err = resources.mDevices.PushBack(device);
        AOS_ERROR_CHECK_AND_THROW("linux devices parsing error", err);
    }

    if (object.Has("memory")) {
        resources.mMemory.SetValue({});

        LinuxMemoryFromJSON(object.GetObject("memory"), *resources.mMemory);
    }

    if (object.Has("cpu")) {
        resources.mCPU.SetValue({});

        LinuxCPUFromJSON(object.GetObject("cpu"), *resources.mCPU);
    }

    if (object.Has("pids")) {
        resources.mPids.SetValue({});

        LinuxPidsFromJSON(object.GetObject("pids"), *resources.mPids);
    }
}

Poco::JSON::Object LinuxResourcesToJSON(const aos::oci::LinuxResources& resources)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    if (!resources.mDevices.IsEmpty()) {
        object.set("devices", utils::ToJsonArray(resources.mDevices, DeviceCgroupToJSON));
    }

    if (resources.mMemory.HasValue()) {
        if (auto memoryObject = LinuxMemoryToJSON(*resources.mMemory); memoryObject.size() > 0) {
            object.set("memory", memoryObject);
        }
    }

    if (resources.mCPU.HasValue()) {
        if (auto cpuObject = LinuxCPUToJSON(resources.mCPU.GetValue()); cpuObject.size() > 0) {
            object.set("cpu", cpuObject);
        }
    }

    if (resources.mPids.HasValue()) {
        object.set("pids", LinuxPidsToJSON(resources.mPids.GetValue()));
    }

    return object;
}

void LinuxNamespaceFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::LinuxNamespace& ns)
{
    const auto type = object.GetValue<std::string>("type");
    const auto path = object.GetValue<std::string>("path");

    aos::oci::LinuxNamespaceType nsType;

    auto err = nsType.FromString(type.c_str());
    AOS_ERROR_CHECK_AND_THROW("linux namespace type parsing error", err);

    ns.mPath = path.c_str();
    ns.mType = nsType;
}

Poco::JSON::Object LinuxNamespaceToJSON(const aos::oci::LinuxNamespace& ns)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    object.set("type", ns.mType.ToString().CStr());

    if (!ns.mPath.IsEmpty()) {
        object.set("path", ns.mPath.CStr());
    }

    return object;
}

void LinuxDeviceFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::LinuxDevice& device)
{
    const auto path = object.GetValue<std::string>("path");
    const auto type = object.GetValue<std::string>("type");

    device.mPath  = path.c_str();
    device.mType  = type.c_str();
    device.mMajor = object.GetValue<int64_t>("major");
    device.mMinor = object.GetValue<int64_t>("minor");

    if (const auto fileMode = object.GetOptionalValue<uint32_t>("fileMode"); fileMode.has_value()) {
        device.mFileMode.SetValue(*fileMode);
    }

    if (const auto uid = object.GetOptionalValue<uint32_t>("uid"); uid.has_value()) {
        device.mUID.SetValue(*uid);
    }

    if (const auto gid = object.GetOptionalValue<uint32_t>("gid"); gid.has_value()) {
        device.mGID.SetValue(*gid);
    }
}

Poco::JSON::Object LinuxDeviceToJSON(const aos::oci::LinuxDevice& device)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    object.set("path", device.mPath.CStr());
    object.set("type", device.mType.CStr());
    object.set("major", device.mMajor);
    object.set("minor", device.mMinor);

    if (device.mFileMode.HasValue()) {
        object.set("fileMode", device.mFileMode.GetValue());
    }

    if (device.mUID.HasValue()) {
        object.set("uid", device.mUID.GetValue());
    }

    if (device.mGID.HasValue()) {
        object.set("gid", device.mGID.GetValue());
    }

    return object;
}

void LinuxFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::Linux& lnx)
{
    if (object.Has("sysctl")) {
        SysctlFromJSON(object.Get("sysctl"), lnx.mSysctl);
    }

    if (object.Has("resources")) {
        lnx.mResources.SetValue({});

        LinuxResourcesFromJSON(object.GetObject("resources"), *lnx.mResources);
    }

    if (const auto cgroupsPath = object.GetValue<std::string>("cgroupsPath"); !cgroupsPath.empty()) {
        lnx.mCgroupsPath = cgroupsPath.c_str();
    }

    const auto namespaces = utils::GetArrayValue<aos::oci::LinuxNamespace>(object, "namespaces", [](const auto& value) {
        aos::oci::LinuxNamespace ns;

        LinuxNamespaceFromJSON(utils::CaseInsensitiveObjectWrapper(value), ns);

        return ns;
    });

    for (const auto& ns : namespaces) {
        auto err = lnx.mNamespaces.PushBack(ns);
        AOS_ERROR_CHECK_AND_THROW("linux namespaces parsing error", err);
    }

    const auto devices = utils::GetArrayValue<aos::oci::LinuxDevice>(object, "devices", [](const auto& value) {
        aos::oci::LinuxDevice device;

        LinuxDeviceFromJSON(utils::CaseInsensitiveObjectWrapper(value), device);

        return device;
    });

    for (const auto& device : devices) {
        auto err = lnx.mDevices.PushBack(device);
        AOS_ERROR_CHECK_AND_THROW("linux devices parsing error", err);
    }

    for (const auto& path : utils::GetArrayValue<std::string>(object, "maskedPaths")) {
        auto err = lnx.mMaskedPaths.EmplaceBack(path.c_str());
        AOS_ERROR_CHECK_AND_THROW("masked paths parsing error", err);
    }

    for (const auto& path : utils::GetArrayValue<std::string>(object, "readonlyPaths")) {
        auto err = lnx.mReadonlyPaths.EmplaceBack(path.c_str());
        AOS_ERROR_CHECK_AND_THROW("readonly paths parsing error", err);
    }
}

Poco::JSON::Object LinuxToJSON(const aos::oci::Linux& lnx)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    if (!lnx.mSysctl.IsEmpty()) {
        object.set("sysctl", SysctlToJSON(lnx.mSysctl));
    }

    if (lnx.mResources.HasValue()) {
        object.set("resources", LinuxResourcesToJSON(lnx.mResources.GetValue()));
    }

    if (!lnx.mCgroupsPath.IsEmpty()) {
        object.set("cgroupsPath", lnx.mCgroupsPath.CStr());
    }

    if (!lnx.mNamespaces.IsEmpty()) {
        object.set("namespaces", utils::ToJsonArray(lnx.mNamespaces, LinuxNamespaceToJSON));
    }

    if (!lnx.mDevices.IsEmpty()) {
        object.set("devices", utils::ToJsonArray(lnx.mDevices, LinuxDeviceToJSON));
    }

    if (!lnx.mMaskedPaths.IsEmpty()) {
        object.set("maskedPaths", utils::ToJsonArray(lnx.mMaskedPaths, ToStdString));
    }

    if (!lnx.mReadonlyPaths.IsEmpty()) {
        object.set("readonlyPaths", utils::ToJsonArray(lnx.mReadonlyPaths, ToStdString));
    }

    return object;
}

void VMHypervisorFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::VMHypervisor& hypervisor)
{
    const auto path       = object.GetValue<std::string>("path");
    const auto parameters = utils::GetArrayValue<std::string>(object, "parameters");

    hypervisor.mPath = path.c_str();

    for (const auto& param : parameters) {
        auto err = hypervisor.mParameters.EmplaceBack(param.c_str());
        AOS_ERROR_CHECK_AND_THROW("hypervisor parameters parsing error", err);
    }
}

Poco::JSON::Object VMHypervisorToJSON(const aos::oci::VMHypervisor& hypervisor)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    object.set("path", hypervisor.mPath.CStr());

    if (!hypervisor.mParameters.IsEmpty()) {
        object.set("parameters", utils::ToJsonArray(hypervisor.mParameters, ToStdString));
    }

    return object;
}

void VMKernelFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::VMKernel& kernel)
{
    const auto path       = object.GetValue<std::string>("path");
    const auto parameters = utils::GetArrayValue<std::string>(object, "parameters");

    kernel.mPath = path.c_str();

    for (const auto& param : parameters) {
        auto err = kernel.mParameters.EmplaceBack(param.c_str());
        AOS_ERROR_CHECK_AND_THROW("kernel parameters parsing error", err);
    }
}

Poco::JSON::Object VMKernelToJSON(const aos::oci::VMKernel& kernel)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    object.set("path", kernel.mPath.CStr());

    if (!kernel.mParameters.IsEmpty()) {
        object.set("parameters", utils::ToJsonArray(kernel.mParameters, ToStdString));
    }

    return object;
}

void VMHWConfigIOMEMFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::VMHWConfigIOMEM& iomem)
{
    iomem.mFirstGFN = object.GetValue<uint64_t>("firstGFN");
    iomem.mFirstMFN = object.GetValue<uint64_t>("firstMFN");
    iomem.mNrMFNs   = object.GetValue<uint64_t>("nrMFNs");
}

Poco::JSON::Array VMHWConfigIOMEMToJSON(const Array<aos::oci::VMHWConfigIOMEM>& iomems)
{
    Poco::JSON::Array jsonArr;

    for (const auto& iomem : iomems) {
        Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

        object.set("firstGFN", iomem.mFirstGFN);
        object.set("firstMFN", iomem.mFirstMFN);
        object.set("nrMFNs", iomem.mNrMFNs);

        jsonArr.add(object);
    }

    return jsonArr;
}

void VMHWConfigFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::VMHWConfig& hwConfig)
{
    const auto deviceTree = object.GetValue<std::string>("deviceTree");
    const auto dtDevs     = utils::GetArrayValue<std::string>(object, "dtDevs");
    const auto irqs       = utils::GetArrayValue<uint32_t>(object, "irqs");

    const auto iomems = utils::GetArrayValue<aos::oci::VMHWConfigIOMEM>(object, "iomems", [](const auto& value) {
        aos::oci::VMHWConfigIOMEM iomem;

        VMHWConfigIOMEMFromJSON(utils::CaseInsensitiveObjectWrapper(value), iomem);

        return iomem;
    });

    hwConfig.mDeviceTree = deviceTree.c_str();
    hwConfig.mVCPUs      = object.GetValue<uint32_t>("vCPUs");
    hwConfig.mMemKB      = object.GetValue<uint64_t>("memKB");

    for (const auto& dev : dtDevs) {
        auto err = hwConfig.mDTDevs.EmplaceBack(dev.c_str());
        AOS_ERROR_CHECK_AND_THROW("dt devices parsing error", err);
    }

    for (const auto& irq : irqs) {
        auto err = hwConfig.mIRQs.PushBack(irq);
        AOS_ERROR_CHECK_AND_THROW("irqs parsing error", err);
    }

    for (const auto& iomem : iomems) {
        auto err = hwConfig.mIOMEMs.PushBack(iomem);
        AOS_ERROR_CHECK_AND_THROW("iomems parsing error", err);
    }
}

Poco::JSON::Object VMHWConfigToJSON(const aos::oci::VMHWConfig& hwConfig)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    if (!hwConfig.mDeviceTree.IsEmpty()) {
        object.set("deviceTree", hwConfig.mDeviceTree.CStr());
    }

    if (hwConfig.mVCPUs > 0) {
        object.set("vCPUs", hwConfig.mVCPUs);
    }

    if (hwConfig.mMemKB > 0) {
        object.set("memKB", hwConfig.mMemKB);
    }

    if (!hwConfig.mDTDevs.IsEmpty()) {
        object.set("dtDevs", utils::ToJsonArray(hwConfig.mDTDevs, ToStdString));
    }

    if (!hwConfig.mIRQs.IsEmpty()) {
        object.set("irqs", utils::ToJsonArray(hwConfig.mIRQs, [](const auto& v) { return v; }));
    }

    if (!hwConfig.mIOMEMs.IsEmpty()) {
        object.set("iomems", VMHWConfigIOMEMToJSON(hwConfig.mIOMEMs));
    }

    return object;
}

void VMFromJSON(const utils::CaseInsensitiveObjectWrapper& object, aos::oci::VM& vm)
{
    if (object.Has("hypervisor")) {
        VMHypervisorFromJSON(object.GetObject("hypervisor"), vm.mHypervisor);
    }

    if (object.Has("kernel")) {
        VMKernelFromJSON(object.GetObject("kernel"), vm.mKernel);
    }

    if (object.Has("hwConfig")) {
        VMHWConfigFromJSON(object.GetObject("hwConfig"), vm.mHWConfig);
    }
}

Poco::JSON::Object VMToJSON(const aos::oci::VM& vm)
{
    Poco::JSON::Object object {Poco::JSON_PRESERVE_KEY_ORDER};

    if (auto hypervisorObject = VMHypervisorToJSON(vm.mHypervisor); hypervisorObject.size() > 0) {
        object.set("hypervisor", hypervisorObject);
    }

    object.set("kernel", VMKernelToJSON(vm.mKernel));

    if (auto hwConfigObject = VMHWConfigToJSON(vm.mHWConfig); hwConfigObject.size() > 0) {
        object.set("hwConfig", hwConfigObject);
    }

    return object;
}

} // namespace

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

Error OCISpec::LoadRuntimeSpec(const String& path, aos::oci::RuntimeSpec& runtimeSpec)
{
    try {
        std::ifstream file(path.CStr());

        if (!file.is_open()) {
            AOS_ERROR_THROW("failed to open file", ErrorEnum::eNotFound);
        }

        auto [var, err] = utils::ParseJson(file);
        AOS_ERROR_CHECK_AND_THROW("failed to parse json", err);

        Poco::JSON::Object::Ptr             object = var.extract<Poco::JSON::Object::Ptr>();
        utils::CaseInsensitiveObjectWrapper wrapper(object);

        const auto ociVersion   = wrapper.GetValue<std::string>("ociVersion");
        runtimeSpec.mOCIVersion = ociVersion.c_str();

        const auto hostname   = wrapper.GetValue<std::string>("hostname");
        runtimeSpec.mHostname = hostname.c_str();

        if (wrapper.Has("process")) {
            auto process = std::make_unique<aos::oci::Process>();

            ProcessFromJSON(wrapper.GetObject("process"), *process);

            runtimeSpec.mProcess.SetValue(*process);
        }

        if (wrapper.Has("root")) {
            runtimeSpec.mRoot.SetValue({});

            RootFromJSON(wrapper.GetObject("root"), *runtimeSpec.mRoot);
        }

        if (wrapper.Has("mounts")) {
            auto mounts = utils::GetArrayValue<Mount>(wrapper, "mounts", [](const auto& value) {
                Mount mount;

                MountFromJSON(utils::CaseInsensitiveObjectWrapper(value), mount);

                return mount;
            });

            for (const auto& mount : mounts) {
                err = runtimeSpec.mMounts.PushBack(mount);
                AOS_ERROR_CHECK_AND_THROW("mounts parsing error", err);
            }
        }

        if (wrapper.Has("linux")) {
            auto lnx = std::make_unique<aos::oci::Linux>();

            LinuxFromJSON(wrapper.GetObject("linux"), *lnx);

            runtimeSpec.mLinux.SetValue(*lnx);
        }

        if (wrapper.Has("vm")) {
            auto vm = std::make_unique<aos::oci::VM>();

            VMFromJSON(wrapper.GetObject("vm"), *vm);

            runtimeSpec.mVM.SetValue(*vm);
        }
    } catch (const utils::AosException& e) {
        return AOS_ERROR_WRAP(Error(e.GetError(), e.message().c_str()));
    } catch (const std::exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

Error OCISpec::SaveRuntimeSpec(const String& path, const aos::oci::RuntimeSpec& runtimeSpec)
{
    try {
        Poco::JSON::Object::Ptr object = new Poco::JSON::Object(Poco::JSON_PRESERVE_KEY_ORDER);

        object->set("ociVersion", runtimeSpec.mOCIVersion.CStr());

        if (runtimeSpec.mProcess.HasValue()) {
            object->set("process", ProcessToJSON(*runtimeSpec.mProcess));
        }

        if (runtimeSpec.mRoot.HasValue()) {
            object->set("root", RootToJSON(runtimeSpec.mRoot.GetValue()));
        }

        if (!runtimeSpec.mHostname.IsEmpty()) {
            object->set("hostname", runtimeSpec.mHostname.CStr());
        }

        if (!runtimeSpec.mMounts.IsEmpty()) {
            object->set("mounts", utils::ToJsonArray(runtimeSpec.mMounts, MountToJSON));
        }

        if (runtimeSpec.mLinux.HasValue()) {
            object->set("linux", LinuxToJSON(runtimeSpec.mLinux.GetValue()));
        }

        if (runtimeSpec.mVM.HasValue()) {
            object->set("vm", VMToJSON(runtimeSpec.mVM.GetValue()));
        }

        auto err = utils::WriteJsonToFile(object, path.CStr());
        AOS_ERROR_CHECK_AND_THROW("failed to write json to file", err);
    } catch (const utils::AosException& e) {
        return AOS_ERROR_WRAP(Error(e.GetError(), e.message().c_str()));
    } catch (const std::exception& e) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, e.what()));
    }

    return ErrorEnum::eNone;
}

} // namespace aos::common::oci
