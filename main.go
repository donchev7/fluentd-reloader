package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func getFluentdIPs(namespace string, clientset *kubernetes.Clientset) ([]string, error) {
	pods, err := clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", namespace),
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get fluentd pods: %w", err)
	}

	fluentdIPs := make([]string, 0, len(pods.Items))
	for _, pod := range pods.Items {
		if _, ok := pod.Labels["statefulset.kubernetes.io/pod-name"]; !ok {
			log.Println("Pod is not from statefulset, skipping", pod.Name)
			continue
		}

		fluentdIPs = append(fluentdIPs, pod.Status.PodIP)
	}

	return fluentdIPs, nil
}

func checkCert(serviceURL string) (time.Time, error) {
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", serviceURL), nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("Server doesn't support SSL certificate err: %w", err)
	}

	err = conn.VerifyHostname(serviceURL)
	if err != nil {
		return time.Time{}, fmt.Errorf("Hostname doesn't match with certificate: %w", err)
	}
	expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
	log.Printf("Issuer: %s\nExpiry: %v\n", conn.ConnectionState().PeerCertificates[0].Issuer, expiry.Format(time.RFC850))

	return expiry, nil
}

func reloadFluentdConfig(ips ...string) error {
	for _, ip := range ips {
		log.Println("Reloading fluentd config on", ip)

		url := fmt.Sprintf("http://%s:24444/api/config.gracefulReload", ip)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		client := &http.Client{
			Timeout: 5 * time.Second,
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send request: %w", err)
		}
		defer resp.Body.Close()

		// check response
		if resp.StatusCode >= 400 {
			return fmt.Errorf("failed to reload fluentd config: %s", resp.Status)
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		log.Printf("Response: %s", string(b))
	}

	return nil
}

func main() {
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}
	namespace, ok := os.LookupEnv("FLUENTD_NAMESPACE")
	if !ok {
		panic("FLUENTD_NAMESPACE is not set")
	}
	serviceURL, ok := os.LookupEnv("FLUENTD_SERVICE_URL")
	if !ok {
		panic("FLUENTD_SERVICE_ENDPOINT is not set")
	}

	fluentdIPs, err := getFluentdIPs(namespace, clientset)
	if err != nil {
		panic(err)
	}

	certificates := cmapi.CertificateList{}
	uri := fmt.Sprintf("/apis/cert-manager.io/v1/namespaces/%s/certificates", namespace)
	err = clientset.RESTClient().Get().RequestURI(uri).Do(context.Background()).Into(&certificates)
	if err != nil {
		panic(err)
	}

	for _, cert := range certificates.Items {
		// cert.Status.NotAfter = When the certificate will expire
		// cert.Status.NotBefore = When the certificate was issued
		// cert.Status.RenewalTime = When the certificate will be renewed

		if !strings.Contains(strings.ToLower(cert.Name), namespace) {
			log.Printf("Certificate %s is not fluentd cerificate", cert.Name)
			continue
		}

		log.Printf("Found certificate %s\n", cert.Name)
		expiry, err := checkCert(serviceURL)
		if err != nil {
			panic(err)
		}

		log.Printf("Certificate will expire on %v\n", expiry)
		t := metav1.NewTime(expiry)
		if cert.Status.NotAfter.Equal(&t) {
			log.Printf("Certificate will be renewed on %v\n", cert.Status.RenewalTime)
			log.Println("Certificate is valid")

			continue
		}

		log.Println("Certificate is not valid")
		log.Printf("Certificate should expire on %v but it expires on %v\n", cert.Status.NotAfter, expiry)
		err = reloadFluentdConfig(fluentdIPs...)
		if err != nil {
			panic(err)
		}
	}
}
