package io.github.marciorodrigues87.route53sslmonitor;

public enum Config {
	SLACK_USERNAME("route-53-ssl-monitor"), //
	SLACK_ICON(":warning:"), //
	SLACK_HOOK("https://hooks.slack.com/services/YOUR_HOOK"), //
	AWS_CREDENTIALS_IDS("KEY_ID_1,KEY_ID_2"), //
	AWS_CREDENTIALS_SECRETS("KEY_SECRET_1,KEY_SECRET_2"), //
	EXPIRATION_THRESHOLD_DAYS("30"), //
	CONNECT_TIMEOUT_MS("500"), //
	READ_TIMEOUT_MS("1000"); //

	private final String value;

	private Config(String value) {
		this.value = value;
	}

	public String[] asStringArray() {
		return asString().split(",");
	}

	public int asInt() {
		return Integer.parseInt(asString());
	}

	public String asString() {
		if (System.getenv(this.name()) != null) {
			return System.getenv(this.name());
		}
		return this.value;
	}
}
