/**
 *
 * \section COPYRIGHT
 *
 * Copyright 2013-2022 Software Radio Systems Limited
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the distribution.
 *
 *
 */
#include "e2sm.h"
#include "e2sm_kpm_common.h"
#include "srsran/asn1/e2ap.h"
#include "srsran/asn1/e2sm.h"
#include "srsran/asn1/e2sm_kpm_v2.h"
#include "srsran/srsran.h"

#ifndef RIC_E2SM_KPM_H
#define RIC_E2SM_KPM_H

using namespace asn1::e2ap;
using namespace asn1::e2sm_kpm;

class e2sm_kpm_report_service;

class e2sm_kpm : public e2sm
{
public:
  static const std::string short_name;
  static const std::string oid;
  static const std::string func_description;
  static const uint32_t    revision;

  e2sm_kpm(srslog::basic_logger& logger_);
  ~e2sm_kpm() = default;

  virtual bool generate_ran_function_description(RANfunction_description& desc, ra_nfunction_item_s& ran_func);
  virtual bool process_ric_event_trigger_definition(ricsubscription_request_s       subscription_request,
                                                    RIC_event_trigger_definition_t& event_def);
  virtual bool process_ric_action_definition(ri_caction_to_be_setup_item_s ric_action, E2AP_RIC_action_t& action_entry);
  virtual bool remove_ric_action_definition(E2AP_RIC_action_t& action_entry);
  virtual bool execute_action_fill_ric_indication(E2AP_RIC_action_t& action_entry, ric_indication_t& ric_indication);

  virtual void receive_e2_metrics_callback(const enb_metrics_t& m);

  bool _get_meas_definition(std::string meas_name, E2SM_KPM_metric_t& def);
  bool _extract_last_integer_type_meas_value(E2SM_KPM_meas_value_t& meas_value, const enb_metrics_t& enb_metrics);
  bool _extract_last_real_type_meas_value(E2SM_KPM_meas_value_t& meas_value, const enb_metrics_t& enb_metrics);
  srslog::basic_logger& logger;

private:
  bool _generate_indication_header(e2_sm_kpm_ind_hdr_s& hdr, srsran::unique_byte_buffer_t& buf);
  bool _generate_indication_message(e2_sm_kpm_ind_msg_s& msg, srsran::unique_byte_buffer_t& buf);

  std::vector<E2SM_KPM_metric_t>               supported_meas_types;
  std::map<uint32_t, e2sm_kpm_report_service*> registered_actions_data;

  srsran_random_t random_gen;

  enb_metrics_t last_enb_metrics;
};

#endif /*E2SM_KPM*/
