/**
 *
 */
#include "srsran/common/gw_pcap.h"
#include "srsran/common/standard_streams.h"
#include "srsran/support/emergency_handlers.h"

namespace srsran {

/// Try to flush the contents of the pcap class before the application is killed.
static void emergency_cleanup_handler(void* data)
{
  reinterpret_cast<gw_pcap*>(data)->close();
}

gw_pcap::gw_pcap() : logger(srslog::fetch_basic_logger("MAC"))
{
  emergency_handler_id = add_emergency_cleanup_handler(emergency_cleanup_handler, this);
}

gw_pcap::~gw_pcap()
{
  if (emergency_handler_id > 0) {
    remove_emergency_cleanup_handler(emergency_handler_id);
  }
}

uint32_t gw_pcap::open(std::string filename_)
{
  std::lock_guard<std::mutex> lock(mutex);
  if (pcap_file != nullptr) {
    return SRSRAN_ERROR;
  }

  // set PDCP DLT
  pcap_file = DLT_PCAP_Open(GW_DLT, filename_.c_str());
  if (pcap_file == nullptr) {
    return SRSRAN_ERROR;
  }

  filename     = filename_;
  enable_write = true;

  return SRSRAN_SUCCESS;
}

uint32_t gw_pcap::close()
{
  fprintf(stdout, "Saving PDCP encrypt PCAP file (DLT=%d) to %s\n", GW_DLT, filename.c_str());
  DLT_PCAP_Close(pcap_file);
  pcap_file = nullptr;

  return SRSRAN_SUCCESS;
}

void gw_pcap::write_ul_gw(uint16_t rnti, uint8_t* pdu, uint32_t pdu_len_bytes)
{
  if (enable_write) {
    GW_Context_Info_t context;
    context.rnti      = rnti;
    context.direction = DIRECTION_UPLINK;
    context.dataType  = 0;

    PCAP_GW_Write_PDU(pcap_file, &context, pdu, pdu_len_bytes);
  }
}

void gw_pcap::write_dl_gw(uint16_t rnti, uint8_t* pdu, uint32_t pdu_len_bytes)
{
  if (enable_write) {
    GW_Context_Info_t context;
    context.rnti      = rnti;
    context.direction = DIRECTION_DOWNLINK;
    context.dataType  = 0;

    PCAP_GW_Write_PDU(pcap_file, &context, pdu, pdu_len_bytes);
  }
}
void gw_pcap::write_mch_gw(uint16_t rnti, uint8_t* pdu, uint32_t pdu_len_bytes)
{
  if (enable_write) {
    GW_Context_Info_t context;
    context.rnti      = rnti;
    context.direction = DIRECTION_DOWNLINK;
    context.dataType  = 1;

    PCAP_GW_Write_PDU(pcap_file, &context, pdu, pdu_len_bytes);
  }
}

} // namespace srsran