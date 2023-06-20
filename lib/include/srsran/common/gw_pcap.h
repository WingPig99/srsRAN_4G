/**
 *
 */
#ifndef SRSRAN_GW_PCAP_H
#define SRSRAN_GW_PCAP_H

#include "srsran/common/pcap.h"
#include "srsran/srslog/srslog.h"
#include "srsran/srsran.h"
#include <mutex>
#include <string>

namespace srsran {

class gw_pcap
{
public:
  gw_pcap();
  ~gw_pcap();
  gw_pcap(const gw_pcap& other)            = delete;
  gw_pcap& operator=(const gw_pcap& other) = delete;
  gw_pcap(gw_pcap&& other)                 = delete;
  gw_pcap& operator=(gw_pcap&& other)      = delete;

  void     enable();
  uint32_t open(std::string filename_);
  uint32_t close();
  void     write_ul_gw(uint16_t rnti, uint8_t* pdu, uint32_t pdu_len_bytes);
  void     write_dl_gw(uint16_t rnti, uint8_t* pdu, uint32_t pdu_len_bytes);
  void     write_mch_gw(uint16_t rnti, uint8_t* pdu, uint32_t pdu_len_bytes);

protected:
  std::mutex            mutex;
  srslog::basic_logger& logger;

private:
  bool        enable_write = false;
  std::string filename;
  FILE*       pcap_file            = nullptr;
  int         emergency_handler_id = -1;
};

} // namespace srsran

#endif // SRSRAN_GW_PCAP_H
