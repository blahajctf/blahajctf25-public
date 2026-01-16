import json
import copy
import time
import inspect

DECIMALS = 10**18

class OracleRegistry:
    def __init__(self):
        self.registered_feeds = {"BLAHAJ_USDC_v1": "0x3a8e9A27AbC7cb3F71691c1B5bf216e72A5D0283"}

    def get_feed_address(self, feed_id):
        return self.registered_feeds.get(feed_id)

class LiquidityEngine:
    def __init__(self, initial_usdc, initial_blahaj):
        self.liquidity_usdc = initial_usdc
        self.liquidity_blahaj = initial_blahaj

    def get_system_rate(self):
        """Calculates the instantaneous exchange rate of BLAHAJ in USDC."""
        if self.liquidity_blahaj == 0 or self.liquidity_usdc == 0:
            return 0
        return (self.liquidity_usdc * DECIMALS) // self.liquidity_blahaj
    
    def commit_to_pool(self, balances, user, usdc_amount=0, blahaj_amount=0):
        if (usdc_amount <= 0 and blahaj_amount <= 0) or \
           (usdc_amount > 0 and blahaj_amount > 0):
            return {"error": "Provide a positive amount for either 'usdc_amount' OR 'blahaj_amount', not both or neither."}

        if self.liquidity_usdc == 0 or self.liquidity_blahaj == 0:
            return {"error": "Liquidity reserve is not initialized. Cannot commit assets proportionally."}
        
        rate = self.get_system_rate()
        
        if usdc_amount > 0:
            required_blahaj = (usdc_amount * DECIMALS) // rate
            final_usdc, final_blahaj = usdc_amount, required_blahaj
        else:
            required_usdc = (blahaj_amount * rate) // DECIMALS
            final_usdc, final_blahaj = required_usdc, blahaj_amount

        if balances[user].get("USDC", 0) < final_usdc:
            return {"error": f"Insufficient USDC balance. Required: {final_usdc} units"}
        if balances[user].get("BLAHAJ", 0) < final_blahaj:
            return {"error": f"Insufficient BLAHAJ balance. Required: {final_blahaj} units"}

        balances[user]["USDC"] -= final_usdc
        balances[user]["BLAHAJ"] -= final_blahaj
        self.liquidity_usdc += final_usdc
        self.liquidity_blahaj += final_blahaj
        
        return {"success": f"Committed {final_usdc} USDC units and {final_blahaj} BLAHAJ units to the reserve."}

    def swap(self, balances, user, from_token, to_token, amount_in):
        if balances[user].get(from_token, 0) < amount_in:
            return {"error": f"Insufficient {from_token} balance."}

        k = self.liquidity_usdc * self.liquidity_blahaj
        amount_out = 0

        if from_token == "USDC" and to_token == "BLAHAJ":
            new_liquidity_usdc = self.liquidity_usdc + amount_in
            new_liquidity_blahaj = k // new_liquidity_usdc
            amount_out = self.liquidity_blahaj - new_liquidity_blahaj
            self.liquidity_usdc, self.liquidity_blahaj = new_liquidity_usdc, new_liquidity_blahaj
        elif from_token == "BLAHAJ" and to_token == "USDC":
            new_liquidity_blahaj = self.liquidity_blahaj + amount_in
            new_liquidity_usdc = k // new_liquidity_blahaj
            amount_out = self.liquidity_usdc - new_liquidity_usdc
            self.liquidity_blahaj, self.liquidity_usdc = new_liquidity_blahaj, new_liquidity_usdc
        else:
            return {"error": f"Invalid token pair for swap: {from_token} to {to_token}."}

        balances[user][from_token] -= amount_in
        balances[user][to_token] = balances[user].get(to_token, 0) + amount_out
        return {"success": f"Swapped {amount_in} {from_token} units for {amount_out} {to_token} units."}


class TreasuryModule:
    def __init__(self, registry_contract, all_contracts_ref):
        self.registry = registry_contract
        self.all_contracts = all_contracts_ref
        self.collateral_factor = 0.6 
        self.total_shares = 0
        self.user_shares = {}
        self.user_debt_blahaj = {}
        self.balance_usdc = 0
        self.balance_blahaj = 0
        self.last_seen_price = 0
        self.last_update_timestamp = 0

    def _fetch_current_rate(self):
        """Internal function to get the rate from the registered data feed."""
        feed_address = self.registry.get_feed_address("BLAHAJ_USDC_v1")
        if not feed_address: return 0
        
        rate_provider = self.all_contracts.get(feed_address)
        if not rate_provider: return 0
        
        return rate_provider.get_system_rate()

    def get_twap_price(self):
        current_time = int(time.time())
        current_price = self._fetch_current_rate()
        
        if current_time - self.last_update_timestamp > 300: 
            self.last_seen_price = current_price
            self.last_update_timestamp = current_time
            return current_price
        
        return (self.last_seen_price + current_price) // 2

    def deposit_usdc(self, balances, user, amount):
        if balances[user].get("USDC", 0) < amount: return {"error": "Insufficient USDC balance."}
        
        rate = self._fetch_current_rate()
        if rate <= 0: return {"error": "Invalid system rate, cannot deposit."}
        
        shares_to_mint = (amount * DECIMALS) // rate
        balances[user]["USDC"] -= amount
        self.balance_usdc += amount
        self.user_shares[user] = self.user_shares.get(user, 0) + shares_to_mint
        self.total_shares += shares_to_mint
        return {"success": f"Deposited {amount} USDC units for {shares_to_mint} share units."}

    def deposit_blahaj(self, balances, user, amount):
        if balances[user].get("BLAHAJ", 0) < amount: return {"error": "Insufficient BLAHAJ balance."}
        balances[user]["BLAHAJ"] -= amount
        self.balance_blahaj += amount
        return {"success": f"Deposited {amount} BLAHAJ units as module liquidity."}

    def withdraw_usdc(self, balances, user, shares_to_burn):
        if self.user_shares.get(user, 0) < shares_to_burn: return {"error": "Insufficient shares."}
        rate = self._fetch_current_rate()
        usdc_to_return = (shares_to_burn * rate) // DECIMALS
        if self.balance_usdc < usdc_to_return: return {"error": "Module has insufficient USDC liquidity."}

        self.user_shares[user] -= shares_to_burn
        self.total_shares -= shares_to_burn
        self.balance_usdc -= usdc_to_return
        balances[user]["USDC"] += usdc_to_return
        return {"success": f"Withdrew {shares_to_burn} share units for {usdc_to_return} USDC units."}

    def borrow_blahaj(self, balances, user, amount_to_borrow):
        rate = self._fetch_current_rate()
        if rate <= 0: return {"error": "Invalid system rate, borrowing disabled."}

        collateral_value = (self.user_shares.get(user, 0) * rate) // DECIMALS
        current_debt_value = (self.user_debt_blahaj.get(user, 0) * rate) // DECIMALS
        max_borrow_power = (collateral_value * self.collateral_factor) - current_debt_value
        max_borrow_blahaj = (max_borrow_power * DECIMALS) // rate

        if amount_to_borrow > max_borrow_blahaj: return {"error": f"Borrow amount exceeds power. Max: {max_borrow_blahaj} BLAHAJ units."}
        if self.balance_blahaj < amount_to_borrow: return {"error": "Module has insufficient BLAHAJ liquidity."}

        self.balance_blahaj -= amount_to_borrow
        balances[user]["BLAHAJ"] = balances[user].get("BLAHAJ", 0) + amount_to_borrow
        self.user_debt_blahaj[user] = self.user_debt_blahaj.get(user, 0) + amount_to_borrow
        return {"success": f"Borrowed {amount_to_borrow} BLAHAJ units."}

    def execute_atomic_batch(self, contracts, balances, user, amount, calls_data):
        if self.balance_blahaj < amount:
            return {"error": "Insufficient liquidity for atomic batch execution."}

        initial_state = copy.deepcopy({
            "b": balances,
            "c": {addr: copy.deepcopy(c.__dict__) for addr, c in contracts.items()}
        })

        self.balance_blahaj -= amount
        balances[user]["BLAHAJ"] = balances[user].get("BLAHAJ", 0) + amount

        results = []
        last_error = None
        for call in calls_data:
            contract = contracts.get(call.get("address"))
            if not contract:
                last_error = f"Contract not found at {call.get('address')}"
                break
            try:
                method = getattr(contract, call.get("function"))
                args = call.get("args", [])
                result = method(balances, user, *args)
                results.append(result)
                if isinstance(result, dict) and "error" in result:
                    last_error = result["error"]
                    break
            except Exception as e:
                last_error = f"Call failed: {e}"
                break

        repayment_amount = amount
        loan_repaid = balances[user].get("BLAHAJ", 0) >= repayment_amount

        if last_error or not loan_repaid:
            for user_id, user_bals in initial_state["b"].items():
                balances[user_id] = user_bals
            for addr, state in initial_state["c"].items():
                contracts[addr].__dict__.update(state)
            
            revert_reason = last_error or "Batch execution failed: credit not repaid."
            return {"error": "Atomic batch reverted", "reason": revert_reason, "sub_call_results": results}

        balances[user]["BLAHAJ"] -= repayment_amount
        self.balance_blahaj += repayment_amount
        
        return {"success": "Atomic batch executed and repaid successfully.", "sub_call_results": results}


class BlockchainSimulator:
    def __init__(self):
        self.balances = {"0x38Dc745781c2C5a16a5d1870876ABFbD1Cec5ac2": {"USDC": 1000 * DECIMALS, "BLAHAJ": 1000 * DECIMALS}}
        
        self.registry = OracleRegistry()
        self.liquidity_engine = LiquidityEngine(10000 * DECIMALS, 10000 * DECIMALS)
        
        self.contracts = {
            "0x3a8e9A27AbC7cb3F71691c1B5bf216e72A5D0283": self.liquidity_engine,
            "0x8d5C4E8C2240954955D30665518462d1A6A34927": self.registry 
        }
        
        self.treasury_module = TreasuryModule(self.registry, self.contracts)
        self.contracts["0x098Ea798EaE10179E5505870095d5a49Db155Fb0"] = self.treasury_module
        
        self.treasury_module.balance_usdc = 1000000 * DECIMALS
        self.treasury_module.balance_blahaj = 1000000 * DECIMALS

    def get_contract_balances(self, contract_address):
        contract = self.contracts.get(contract_address)
        if not contract: return {"error": f"Contract not found at {contract_address}"}
        balances = {}
        if hasattr(contract, 'liquidity_usdc'):
            balances['USDC'] = contract.liquidity_usdc
            balances['BLAHAJ'] = contract.liquidity_blahaj
        elif hasattr(contract, 'balance_usdc'):
            balances['USDC'] = contract.balance_usdc
            balances['BLAHAJ'] = contract.balance_blahaj
        return {k: f"{v} units" for k, v in balances.items()}

    def get_user_balance(self, user, token=None):
        if user not in self.balances: return {"error": f"User '{user}' not found."}
        user_balances = self.balances[user]
        if token:
            return {token: f"{user_balances.get(token, 0)} units"}
        else:
            return {k: f"{v} units" for k, v in user_balances.items()}

    def getFlag(self):
        if self.treasury_module.balance_usdc <= 0:
            f = open("flag", "r")
            flag = f.read()
            f.close()
            return {"flag": flag}
        else:
            usdc_left = self.treasury_module.balance_usdc
            return {"error": f"Module not drained yet. {usdc_left} USDC units remaining."}

    def process_transaction(self, tx_json_string):
        try:
            tx = json.loads(tx_json_string)
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON."}, indent=2)

        user = tx.get("user")
        if not user: return json.dumps({"error": "Missing 'user'."}, indent=2)
        if user not in self.balances: self.balances[user] = {}

        results = []
        for call in tx.get("calls", []):
            function_name = call.get("function")
            args = call.get("args", [])

            if function_name in ["get_contract_balances", "get_user_balance", "getFlag"]:
                target_func = getattr(self, function_name)
            else:
                contract = self.contracts.get(call.get("address"))
                if not contract:
                    results.append({"error": f"Contract not found at {call.get('address')}"})
                    continue
                target_func = getattr(contract, function_name, None)
                if not target_func:
                    results.append({"error": f"Function '{function_name}' not found on contract at {call.get('address')}"})
                    continue

            # Argument count check
            try:
                sig = inspect.signature(target_func)
                # Adjust for 'self', 'balances', 'user', 'contracts' which are passed implicitly
                implicit_args = 0
                if 'self' in sig.parameters: implicit_args += 1
                if 'balances' in sig.parameters: implicit_args += 1
                if 'user' in sig.parameters: implicit_args += 1
                if 'contracts' in sig.parameters: implicit_args += 1
                
                # Check for varargs
                has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in sig.parameters.values())

                min_args = len([p for p in sig.parameters.values() if p.default is inspect.Parameter.empty]) - implicit_args
                
                if not has_varargs and len(args) != (len(sig.parameters) - implicit_args):
                     if len(args) < min_args:
                           results.append({"error": f"Too few arguments for {function_name}. Expected {min_args}, got {len(args)}."})
                           continue
                     if len(args) > len(sig.parameters) - implicit_args:
                           results.append({"error": f"Too many arguments for {function_name}. Expected {len(sig.parameters) - implicit_args}, got {len(args)}."})
                           continue

            except (ValueError, TypeError) as e:
                results.append({"error": f"Could not inspect function signature for {function_name}: {e}"})
                continue


            # Call the function
            try:
                if function_name == "execute_atomic_batch":
                    result = target_func(self.contracts, self.balances, user, *args)
                elif function_name in ["get_contract_balances", "get_user_balance", "getFlag"]:
                     result = target_func(*args)
                else:
                    result = target_func(self.balances, user, *args)
                results.append(result)

            except Exception as e:
                results.append({"error": f"Execution of {function_name} failed: {e}"})

        return json.dumps({"status": "Transaction processed", "results": results})

def main():
    sim = BlockchainSimulator()
    
    print("\n--- Initial State ---")
    print(f"Player Balances: {sim.get_user_balance('0x38Dc745781c2C5a16a5d1870876ABFbD1Cec5ac2')}")
    print(f"Liquidity Engine (0x3a8e9A27AbC7cb3F71691c1B5bf216e72A5D0283) Reserves: {sim.get_contract_balances('0x3a8e9A27AbC7cb3F71691c1B5bf216e72A5D0283')}")
    print(f"Treasury Module (0x098Ea798EaE10179E5505870095d5a49Db155Fb0) Balances: {sim.get_contract_balances('0x098Ea798EaE10179E5505870095d5a49Db155Fb0')}")
    print("-" * 60)

    while True:
        try:
            data = input("> ")
            response = sim.process_transaction(data)
            print(response)
        except EOFError:
            exit(0)
        except:
            return

if __name__ == '__main__':
    main()