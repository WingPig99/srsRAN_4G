/**
 *
 */

#include "srsran/common/pdcp_pcap.h"
#include "srsran/common/standard_streams.h"
#include "srsran/support/emergency_handlers.h"

namespace srsran {

/// Try to flush the contents of the pcap class before the application is killed.
static void emergency_cleanup_handler(void* data)
{
  reinterpret_cast<pdcp_pcap*>(data)->close();
}

pdcp_pcap::pdcp_pcap() : logger(srslog::fetch_basic_logger("MAC"))
{
  emergency_handler_id = add_emergency_cleanup_handler(emergency_cleanup_handler, this);
}

pdcp_pcap::~pdcp_pcap()
{
  if (emergency_handler_id > 0) {
    remove_emergency_cleanup_handler(emergency_handler_id);
  }
}

uint32_t pdcp_pcap::open(std::string filename_)
{
  std::lock_guard<std::mutex> lock(mutex);
  if (pcap_file != nullptr) {
    return SRSRAN_ERROR;
  }

  // set PDCP DLT
  pcap_file = DLT_PCAP_Open(PDCP_DLT, filename_.c_str());
  if (pcap_file == nullptr) {
    return SRSRAN_ERROR;
  }

  filename     = filename_;
  enable_write = true;

  return SRSRAN_SUCCESS;
}

uint32_t pdcp_pcap::close()
{
  fprintf(stdout, "Saving PDCP encrypt PCAP file (DLT=%d) to %s\n", PDCP_DLT, filename.c_str());
  DLT_PCAP_Close(pcap_file);
  pcap_file = nullptr;

  return SRSRAN_SUCCESS;
}

void pdcp_pcap::write_ul_pdcp(uint16_t rnti, uint32_t eps_bearer_id, int32_t sn, uint8_t* pdu, uint32_t pdu_len_bytes)
{
  if (enable_write) {
    PDCP_Context_Info_t context;
    context.rnti      = rnti;
    context.channelId = uint8_t(eps_bearer_id);
    context.direction = DIRECTION_UPLINK;
    context.sn        = sn;

    PCAP_PDCP_Write_PDU(pcap_file, &context, pdu, pdu_len_bytes);
  }
}

void pdcp_pcap::write_dl_pdcp(uint16_t rnti, uint32_t eps_bearer_id, int32_t sn, uint8_t* pdu, uint32_t pdu_len_bytes)
{
  if (enable_write) {
    PDCP_Context_Info_t context;
    context.rnti      = rnti;
    context.channelId = uint8_t(eps_bearer_id);
    context.direction = DIRECTION_DOWNLINK;
    context.sn        = sn;

    PCAP_PDCP_Write_PDU(pcap_file, &context, pdu, pdu_len_bytes);
  }
}

} // namespace srsran