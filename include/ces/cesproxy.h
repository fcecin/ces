#pragma once

/**
 * CesProxy — MinxProxy subclass with CES-level message validation.
 *
 * - Signed messages: verify signature before forwarding
 * - Unsigned messages: validate opcode and structure
 * - Unknown opcodes: drop + close
 * - PoW: verify RandomX hash locally before forwarding
 *
 * Only the general-purpose server request/response lane (MINX_MESSAGE) is
 * proxied. The APPLICATION push lane (CES_APP_COMPUTE_MSG) is intentionally
 * NOT proxied: compute programs are reachable only over a direct UDP
 * connection.
 */

#include <ces/keys.h>
#include <ces/protocol.h>
#include <ces/types.h>
#include <minx/proxy/minxproxy.h>

class CesProxy : public minx::MinxProxy {
public:
  using MinxProxy::MinxProxy; // inherit constructors

protected:
  bool filterMessage(const minx::TcpSessionPtr& session,
                     const minx::MinxMessage& msg) override {
    if (msg.data.empty())
      return false;

    uint8_t opCode = msg.data[0];

    switch (opCode) {

      // --- Signed messages: extract key, verify signature ---

    case ces::CES_TRANSFER: {
      ces::CesTransfer req;
      return verifySigned(msg.data, req, req.originId);
    }
    case ces::CES_OPEN_TRANSFER: {
      ces::CesOpenTransfer req;
      return verifySigned(msg.data, req, req.originId);
    }
    case ces::CES_CREATE_PAYMENT: {
      ces::CesCreatePayment req;
      return verifySigned(msg.data, req, req.originId);
    }
    case ces::CES_CROSS_TRANSFER: {
      ces::CesCrossTransfer req;
      return verifySigned(msg.data, req, req.originId);
    }
    case ces::CES_RUN_ASSET: {
      ces::CesRunAsset req;
      return verifySigned(msg.data, req, req.originId);
    }
    case ces::CES_BULK_TRANSFER: {
      ces::CesBulkTransfer req;
      return verifySigned(msg.data, req, req.originId);
    }
    case ces::CES_QUERY_ACCOUNT: {
      ces::CesQueryAccount req;
      return verifySigned(msg.data, req, req.originId);
    }
    case ces::CES_CREATE_ASSET: {
      ces::CesCreateAsset req;
      return verifySigned(msg.data, req, req.ownerId);
    }
    case ces::CES_UPDATE_ASSET: {
      ces::CesUpdateAsset req;
      return verifySigned(msg.data, req, req.ownerId);
    }
    case ces::CES_UPDATE_ASSET_META: {
      ces::CesUpdateAssetMeta req;
      return verifySigned(msg.data, req, req.ownerId);
    }
    case ces::CES_UPDATE_ASSET_FAST: {
      ces::CesUpdateAssetFast req;
      return verifySigned(msg.data, req, req.ownerId);
    }
    case ces::CES_FUND_ASSET: {
      ces::CesFundAsset req;
      return verifySigned(msg.data, req, req.originId);
    }
    case ces::CES_BUY_ASSET: {
      ces::CesBuyAsset req;
      return verifySigned(msg.data, req, req.originId);
    }
    case ces::CES_GIVE_ASSET: {
      ces::CesGiveAsset req;
      return verifySigned(msg.data, req, req.ownerId);
    }
    case ces::CES_QUERY_ASSET: {
      ces::CesQueryAsset req;
      return verifySigned(msg.data, req, req.originId);
    }
    case ces::CES_QUERY_SERVER_INFO: {
      ces::CesQueryServerInfo req;
      return verifySigned(msg.data, req, req.originId);
    }

      // --- Unsigned messages: validate structure only ---

    case ces::CES_UNSIGNED_QUERY_ACCOUNT: {
      ces::CesUnsignedQueryAccount req;
      return verifyUnsigned(msg.data, req);
    }
    case ces::CES_UNSIGNED_QUERY_SOLUTION: {
      ces::CesUnsignedQuerySolution req;
      return verifyUnsigned(msg.data, req);
    }
    case ces::CES_UNSIGNED_QUERY_ASSET: {
      ces::CesUnsignedQueryAsset req;
      return verifyUnsigned(msg.data, req);
    }

    default:
      return false; // unknown opcode → drop
    }
  }

  bool filterProveWork(const minx::TcpSessionPtr& session,
                       const minx::MinxProveWork& msg) override {
    return verifyProveWork(msg);
  }

private:
  template <typename Req>
  bool verifySigned(const minx::Bytes& data, Req& req,
                    const minx::Hash& keyField) {
    try {
      req.fromBytes(data);
      return req.verifySignature(data, ces::PublicKey(keyField));
    } catch (...) {
      return false;
    }
  }

  template <typename Req>
  bool verifyUnsigned(const minx::Bytes& data, Req& req) {
    try {
      req.fromBytes(data);
      return true;
    } catch (...) {
      return false;
    }
  }
};
