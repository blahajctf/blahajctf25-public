function delay_request(txn)
  core.msleep(math.random(500))
end

core.register_action("delay_request", { "http-req" }, delay_request)
