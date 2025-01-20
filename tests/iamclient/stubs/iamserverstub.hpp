/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IAMPUBLICSERVICE_HPP
#define IAMPUBLICSERVICE_HPP

#include <grpcpp/security/credentials.h>
#include <grpcpp/server_builder.h>

#include <iamanager/v5/iamanager.grpc.pb.h>

#include <aos/iam/certhandler.hpp>

/**
 * Test IAM server.
 */
class TestIAMServerStub final : public iamanager::v5::IAMPublicService::Service,
                                public iamanager::v5::IAMPermissionsService::Service {
public:
    /**
     * Constructor.
     */
    TestIAMServerStub() { mServer = CreateServer(); }

    /**
     * Get certificate type.
     *
     * @return Certificate type.
     */
    std::string GetCertType() const { return mCertType; }

    /**
     * Set certificate info.
     *
     * @param certInfo Certificate info.
     */
    void SetCertInfo(const aos::iam::certhandler::CertInfo& certInfo) { mCertInfo = certInfo; }

    /**
     * Send certificate changed info.
     *
     * @param certInfo Certificate info.
     * @return True if success.
     */
    bool SendCertChangedInfo(const iamanager::v5::CertInfo& certInfo)
    {
        mCertInfo.mCertURL = certInfo.cert_url().c_str();
        mCertInfo.mKeyURL  = certInfo.key_url().c_str();

        return mStream->Write(certInfo);
    }

    /**
     * Wait for connection.
     *
     * @return True if connected.
     */
    bool WaitForConnection()
    {
        std::unique_lock lock {mLock};

        mCV.wait_for(lock, kTimeout, [this] { return mConnected; });

        return mConnected;
    }

    /**
     * Close server.
     */
    void Close()
    {
        {
            std::lock_guard lock {mLock};
            mClose = true;
        }

        mCV.notify_all();
    }

private:
    constexpr static std::chrono::seconds kTimeout = std::chrono::seconds(5);

    std::unique_ptr<grpc::Server> CreateServer()
    {
        grpc::ServerBuilder builder;
        builder.AddListeningPort("localhost:8002", grpc::InsecureServerCredentials());
        builder.RegisterService(static_cast<iamanager::v5::IAMPublicService::Service*>(this));
        builder.RegisterService(static_cast<iamanager::v5::IAMPermissionsService::Service*>(this));

        return builder.BuildAndStart();
    }

    grpc::Status GetCert(
        grpc::ServerContext*, const iamanager::v5::GetCertRequest* request, iamanager::v5::CertInfo* response) override
    {

        mCertType = request->type();

        response->set_cert_url(mCertInfo.mCertURL.CStr());
        response->set_key_url(mCertInfo.mKeyURL.CStr());

        return grpc::Status::OK;
    }

    grpc::Status GetNodeInfo(grpc::ServerContext*, [[maybe_unused]] const google::protobuf::Empty* request,
        iamanager::v5::NodeInfo* response) override
    {
        response->set_node_id("node_id");
        response->set_node_type("node_type");
        response->set_name("name");
        response->set_status("provisioned");
        response->set_os_type("os_type");

        iamanager::v5::CPUInfo* cpuInfo = response->add_cpus();
        cpuInfo->set_model_name("model_name");
        cpuInfo->set_num_cores(1);
        cpuInfo->set_num_threads(1);
        cpuInfo->set_arch("arch");
        cpuInfo->set_arch_family("arch_family");
        cpuInfo->set_max_dmips(1);

        response->set_max_dmips(1);
        response->set_total_ram(1);

        iamanager::v5::PartitionInfo* partitionInfo = response->add_partitions();
        partitionInfo->set_name("name");
        partitionInfo->add_types("types");
        partitionInfo->set_total_size(1);
        partitionInfo->set_path("path");

        iamanager::v5::NodeAttribute* nodeAttribute = response->add_attrs();
        nodeAttribute->set_name("name");
        nodeAttribute->set_value("value");

        return grpc::Status::OK;
    }

    grpc::Status SubscribeCertChanged(grpc::ServerContext*, const iamanager::v5::SubscribeCertChangedRequest* request,
        grpc::ServerWriter<iamanager::v5::CertInfo>* writer) override
    {
        mCertType = request->type();

        mStream = writer;

        mConnected = true;
        mCV.notify_all();

        {
            std::unique_lock lock {mLock};
            mCV.wait(lock, [this] { return mClose; });
        }

        return grpc::Status::OK;
    }

    grpc::Status RegisterInstance(grpc::ServerContext*, [[maybe_unused]] const iamanager::v5::RegisterInstanceRequest*,
        iamanager::v5::RegisterInstanceResponse* response) override
    {
        response->set_secret("secret");

        return grpc::Status::OK;
    }

    grpc::Status UnregisterInstance(
        grpc::ServerContext*, const iamanager::v5::UnregisterInstanceRequest*, google::protobuf::Empty*) override
    {
        return grpc::Status::OK;
    }

    std::unique_ptr<grpc::Server>                mServer;
    std::string                                  mCertType;
    aos::iam::certhandler::CertInfo              mCertInfo;
    grpc::ServerWriter<iamanager::v5::CertInfo>* mStream {};
    std::mutex                                   mLock;
    std::condition_variable                      mCV;
    bool                                         mConnected = false;
    bool                                         mClose     = false;
};

#endif // IAMPUBLICSERVICE_HPP
