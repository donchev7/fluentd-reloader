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

type app struct {
	namespace string
	certName  string
	client    *kubernetes.Clientset
}

type config struct {
	serviceURL string
	certName   string
	namespace  string
}

func getConfig() config {
	serviceURL, ok := os.LookupEnv("FLUENTD_SERVICE_URL")
	if !ok {
		panic("FLUENTD_SERVICE_URL is not set")
	}

	certName, ok := os.LookupEnv("FLUENTD_CERT_NAME")
	if !ok {
		panic("FLUENTD_CERT_NAME is not set")
	}

	namespace, ok := os.LookupEnv("FLUENTD_NAMESPACE")
	if !ok {
		panic("FLUENTD_NAMESPACE is not set")
	}

	return config{
		serviceURL: serviceURL,
		certName:   certName,
		namespace:  namespace,
	}
}

// get all pods with label app=fluentd in the configured namespace
// note that this will only work if the pods are created by a statefulset
func (a app) getFluentdIPs() ([]string, error) {
	pods, err := a.client.CoreV1().Pods(a.namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", a.namespace),
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

func (a app) getCRD() (cmapi.Certificate, error) {
	certificates := cmapi.CertificateList{}
	uri := fmt.Sprintf("/apis/cert-manager.io/v1/namespaces/%s/certificates", a.namespace)
	err := a.client.RESTClient().Get().RequestURI(uri).Do(context.Background()).Into(&certificates)
	if err != nil {
		return cmapi.Certificate{}, fmt.Errorf("failed to get certificates: %w", err)
	}

	for _, cert := range certificates.Items {
		if strings.EqualFold(cert.Name, a.certName) {
			return cert, nil
		}

		log.Printf("Certificate %s is not fluentd cerificate", cert.Name)
	}

	return cmapi.Certificate{}, fmt.Errorf("failed to find fluentd certificate")
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
	// setup kubernetes client with default config
	// works both locally if you have kubectl correctly configured and in cluster
	cfg, err := rest.InClusterConfig()
	if err != nil {
		panic(err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		panic(err)
	}

	config := getConfig()
	app := app{
		namespace: config.namespace,
		certName:  config.certName,
		client:    clientset,
	}

	fluentdIPs, err := app.getFluentdIPs()
	if err != nil {
		panic(err)
	}

	expiry, err := checkCert(config.serviceURL)
	if err != nil {
		panic(err)
	}

	certificate, err := app.getCRD()
	if err != nil {
		panic(err)
	}

	log.Printf("Certificate will expire on %v\n", expiry)
	t := metav1.NewTime(expiry)
	if certificate.Status.NotAfter.Equal(&t) {
		log.Printf("Certificate will be renewed on %v\n", certificate.Status.RenewalTime)
		log.Println("Certificate is valid")

		return
	}

	log.Println("Certificate is not valid")
	log.Printf("Certificate should expire on %v but it expires on %v\n", certificate.Status.NotAfter, expiry)
	err = reloadFluentdConfig(fluentdIPs...)
	if err != nil {
		panic(err)
	}
}
