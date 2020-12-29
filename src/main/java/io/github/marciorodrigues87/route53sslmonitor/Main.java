package io.github.marciorodrigues87.route53sslmonitor;

import static io.github.marciorodrigues87.route53sslmonitor.Config.AWS_CREDENTIALS_IDS;
import static io.github.marciorodrigues87.route53sslmonitor.Config.AWS_CREDENTIALS_SECRETS;
import static io.github.marciorodrigues87.route53sslmonitor.Config.CONNECT_TIMEOUT_MS;
import static io.github.marciorodrigues87.route53sslmonitor.Config.EXPIRATION_THRESHOLD_DAYS;
import static io.github.marciorodrigues87.route53sslmonitor.Config.READ_TIMEOUT_MS;
import static io.github.marciorodrigues87.route53sslmonitor.Config.SLACK_HOOK;
import static io.github.marciorodrigues87.route53sslmonitor.Config.SLACK_ICON;
import static io.github.marciorodrigues87.route53sslmonitor.Config.SLACK_USERNAME;
import static java.lang.String.format;
import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static software.amazon.awssdk.regions.Region.AWS_GLOBAL;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.services.route53.Route53Client;
import software.amazon.awssdk.services.route53.model.ListResourceRecordSetsRequest;
import software.amazon.awssdk.services.route53.model.RRType;
import software.amazon.awssdk.services.route53.model.ResourceRecordSet;

public class Main {

	public static void main(String[] args) throws Exception {
		final var sc = SSLContext.getInstance("SSL");
		sc.init(null, new TrustManager[] { new X509TrustManager() {
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
			}

			public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
			}
		} }, new java.security.SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
			@Override
			public boolean verify(String hostname, SSLSession sslSession) {
				return true;
			}
		});
		HttpsURLConnection.setFollowRedirects(false);

		final var keyIds = AWS_CREDENTIALS_IDS.asStringArray();
		final var keySecrets = AWS_CREDENTIALS_SECRETS.asStringArray();
		final var result = new CheckResult();
		for (int i = 0; i < keyIds.length; i++) {
			try {
				checkAccount(keyIds[i], keySecrets[i], result);
			} catch (Exception e) {
				e.printStackTrace();
				System.exit(-1);
			}
		}
		
		sendSlackMessage(result.toString());
		System.out.println("**** END ****");
	}

	private static void checkAccount(String keyId, String keySecret, CheckResult result) {
		final var provider = StaticCredentialsProvider.create(AwsBasicCredentials.create(keyId, keySecret));
		final var client = Route53Client.builder().region(AWS_GLOBAL).credentialsProvider(provider).build();
		final var response = client.listHostedZones();
		for (var hostedZone : response.hostedZones()) {
			final var recordSets = client.listResourceRecordSets(
					ListResourceRecordSetsRequest.builder().hostedZoneId(hostedZone.id()).build());
			for (var rs : recordSets.resourceRecordSets()) {
				if (isWildcard(rs) || !shouldBeChecked(rs) || !isListeningForSsl(rs)) {
					continue;
				}
				HttpsURLConnection conn = null;
				try {
					final var host = rs.name().substring(0, rs.name().length() - 1);
					final var url = new URL(format("https://%s", host));
					conn = (HttpsURLConnection) url.openConnection();
					conn.setReadTimeout(READ_TIMEOUT_MS.asInt());
					conn.setConnectTimeout(CONNECT_TIMEOUT_MS.asInt());
					conn.connect();

					if (conn.getServerCertificates() != null && conn.getServerCertificates().length > 0) {
						var cert = conn.getServerCertificates()[0];
						if (cert instanceof X509Certificate) {
							var x509 = (X509Certificate) cert;
							try {
								x509.checkValidity();
								final var days = DAYS.convert(x509.getNotAfter().getTime() - new Date().getTime(), MILLISECONDS);
								if (days <= EXPIRATION_THRESHOLD_DAYS.asInt()) {
									result.addNearExpiration(format("%s expira em %d dias", host, days));
									System.out.println(format("certificate near expiration (%s) in %s - %s", x509.getNotAfter(), rs.name(),
											x509.getSubjectX500Principal()));
								}
							} catch (CertificateExpiredException cee) {
								System.out.println(format("certificate is expired in %s - %s", rs.name(),
										x509.getSubjectX500Principal()));
								result.addExpired(host);
							}
						}
					}
				} catch (Exception e) {
					var cause = e.getCause() != null ? e.getCause() : e;
					System.out.println(format("invalid ssl connection in %s - error: %s - %s", rs.name(),
							e.getMessage(), cause.getClass()));

				} finally {
					if (conn != null) {
						conn.disconnect();
					}
				}
			}
		}
	}

	private static boolean shouldBeChecked(ResourceRecordSet rs) {
		return rs.type() == RRType.CNAME || rs.type() == RRType.A;
	}

	private static boolean isWildcard(ResourceRecordSet rs) {
		return rs.name().startsWith("\\052");
	}

	private static boolean isListeningForSsl(ResourceRecordSet rs) {
		try (var s = new Socket()) {
			s.connect(new InetSocketAddress(rs.name(), 443), CONNECT_TIMEOUT_MS.asInt());
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	private static void sendSlackMessage(String payload) throws IOException, InterruptedException {
		final HttpRequest slackPost = HttpRequest.newBuilder().uri(URI.create(SLACK_HOOK.asString()))
				.POST(BodyPublishers.ofString(format("{\"username\":\"%s\",\"icon_emoji\":\"%s\",\"text\": \"%s\"}",
						SLACK_USERNAME.asString(), SLACK_ICON.asString(), payload)))
				.build();
		final String bodyResponse = HttpClient.newHttpClient().send(slackPost, BodyHandlers.ofString()).body();
		System.out.println(format("**** SLACK %s ****", bodyResponse));
	}

	private static class CheckResult {

		private final List<String> expired;
		private final List<String> nearExpiration;

		public CheckResult() {
			this.expired = new ArrayList<>();
			this.nearExpiration = new ArrayList<>();
		}

		public void addExpired(String expired) {
			this.expired.add(expired);
		}
		
		public void addNearExpiration(String nearExpiration) {
			this.nearExpiration.add(nearExpiration);
		}
		
		@Override
		public String toString() {
			if (expired.isEmpty() && nearExpiration.isEmpty()) {
				return "carai muleque, não tem nada de certificado com problema hoje";
			}
			final var payload = new StringBuilder("migos, ");
			if (!expired.isEmpty()) {
				payload.append("achei esses certificados expirados no nosso DNS\n");
				payload.append("```\n");
				for (var item : expired) {
					payload.append(format("%s\n", item));
				}
				payload.append("```\n");
			}
			if (!nearExpiration.isEmpty()) {
				payload.append("tem esses certificado aqui que estão perto de expirar");
				if (!expired.isEmpty()) {
					payload.append(" também");
				}
				payload.append("\n");
				payload.append("```\n");
				for (var item : nearExpiration) {
					payload.append(format("%s\n", item));
				}
				payload.append("```\n");
			}
			payload.append("se vcs pudessem dar uma olhada, me ajudaria, please?");
			return payload.toString();
		}
	}
}
