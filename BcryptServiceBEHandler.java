import java.util.ArrayList;
import java.util.List;

import org.mindrot.jbcrypt.BCrypt;

public class BcryptServiceBEHandler implements BcryptServiceBE.Iface {

	public List<String> hashPassword(List<String> password, short logRounds) throws IllegalArgument, org.apache.thrift.TException
	{
		int numPass = password.size();
		List<String> ret = new ArrayList<>(numPass);
		try {
			//Split even number of passwords across both threads
			if (numPass == 8) {
				ThreadedHash backendThread = new ThreadedHash(password.subList(4, 8), logRounds);
				Thread threadBE = new Thread(backendThread);
				threadBE.start();
				for (int i = 0; i < 4; ++i) {
					String onePwd = password.get(i);
					String oneHash = BCrypt.hashpw(onePwd, BCrypt.gensalt(logRounds));
					ret.add(oneHash);
				}
				threadBE.join();
				ret.addAll(backendThread.ret);
			}
			else if (numPass == 6) {
				ThreadedHash backendThread = new ThreadedHash(password.subList(3, 6), logRounds);
				Thread threadBE = new Thread(backendThread);
				threadBE.start();
				for (int i = 0; i < 3; ++i) {
					String onePwd = password.get(i);
					String oneHash = BCrypt.hashpw(onePwd, BCrypt.gensalt(logRounds));
					ret.add(oneHash);
				}
				threadBE.join();
				ret.addAll(backendThread.ret);
			}
			else if (numPass == 4) {
				ThreadedHash backendThread = new ThreadedHash(password.subList(2, 4), logRounds);
				Thread threadBE = new Thread(backendThread);
				threadBE.start();
				for (int i = 0; i < 2; ++i) {
					String onePwd = password.get(i);
					String oneHash = BCrypt.hashpw(onePwd, BCrypt.gensalt(logRounds));
					ret.add(oneHash);
				}
				threadBE.join();
				ret.addAll(backendThread.ret);
			}
			else {
				String onePwd = password.get(0);
				String oneHash = BCrypt.hashpw(onePwd, BCrypt.gensalt(logRounds));
				ret.add(oneHash);
			}
			return ret;
		} catch (Exception e) {
			return ret;
		}
	}

	public List<Boolean> checkPassword(List<String> password, List<String> hash) throws IllegalArgument, org.apache.thrift.TException
	{
		int numPass = password.size();
		List<Boolean> ret = new ArrayList<>(numPass);
		try {
			//Split even number of passwords across both threads
			if (numPass == 8) {
				ThreadedCheck backendThread = new ThreadedCheck(password.subList(4, 8), hash.subList(4, 8));
				Thread threadBE = new Thread(backendThread);
				threadBE.start();
				for (int i = 0; i < 4; ++i) {
					String onePwd = password.get(i);
					String oneHash = hash.get(i);
					ret.add(BCrypt.checkpw(onePwd, oneHash));
				}
				threadBE.join();
				ret.addAll(backendThread.ret);
			}
			else if (numPass == 6) {
				ThreadedCheck backendThread = new ThreadedCheck(password.subList(3, 6), hash.subList(3, 6));
				Thread threadBE = new Thread(backendThread);
				threadBE.start();
				for (int i = 0; i < 3; ++i) {
					String onePwd = password.get(i);
					String oneHash = hash.get(i);
					ret.add(BCrypt.checkpw(onePwd, oneHash));
				}
				threadBE.join();
				ret.addAll(backendThread.ret);
			}
			else if (numPass == 4) {
				ThreadedCheck backendThread = new ThreadedCheck(password.subList(2, 4), hash.subList(2, 4));
				Thread threadBE = new Thread(backendThread);
				threadBE.start();
				for (int i = 0; i < 2; ++i) {
					String onePwd = password.get(i);
					String oneHash = hash.get(i);
					ret.add(BCrypt.checkpw(onePwd, oneHash));
				}
				threadBE.join();
				ret.addAll(backendThread.ret);
			}
			else {
				String onePwd = password.get(0);
				String oneHash = hash.get(0);
				ret.add(BCrypt.checkpw(onePwd, oneHash));
			}
			return ret;
		} catch (Exception e) {
			return ret;
		}
	}
}

class ThreadedHash extends Thread {
	List<String> password;
	List<String> ret;
	short logRounds;
	ThreadedHash(List<String> password, short logRounds)
	{
		this.password = password;
		this.logRounds = logRounds;
		this.ret = new ArrayList<>(password.size());
	}
	public void run() 
	{
		try {
			for (int i = 0; i < password.size(); ++i) {
				String onePwd = password.get(i);
				String oneHash = BCrypt.hashpw(onePwd, BCrypt.gensalt(logRounds));
				ret.add(oneHash);
			}
		} catch (Exception e) {}
	}
}

class ThreadedCheck extends Thread
{
	List<String> password;
	List<String> hash;
	List<Boolean> ret;
	ThreadedCheck(List<String> password, List<String> hash)
	{
		this.password = password;
		this.hash = hash;
		this.ret = new ArrayList<>(password.size());
	}
	public void run() 
	{
		try {
			for (int i = 0; i < password.size(); ++i) {
				String onePwd = password.get(i);
				String oneHash = hash.get(i);
				ret.add(BCrypt.checkpw(onePwd, oneHash));
			}
		} catch (Exception e) {}
	}
}