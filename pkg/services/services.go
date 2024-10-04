package services

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ShebinSp/Dencryptor/pkg/auth"
	"github.com/ShebinSp/Dencryptor/pkg/config"
	"github.com/ShebinSp/Dencryptor/pkg/models"
	"github.com/ShebinSp/Dencryptor/pkg/utils"
	"gorm.io/gorm"
)

// type datas struct {
// 	images []models.ImageData
// }

// to save locally
// func (d *datas) addData(img models.ImageData) error {
// 	d.images = append(d.images, img)
// 		fmt.Println("Size of datas: ", len(d.images))
// 		return nil
// }

func addData(img *models.ImageData) (*gorm.DB, error) {
	db, _ := config.Config()
	res := db.Create(&img)
	if res.Error != nil || res.RowsAffected == 0 {
		return nil, fmt.Errorf("failed to save file")
	}

	return db, nil
}

// var data datas

func EncodeImage(w http.ResponseWriter, r *http.Request) {
	var wg sync.WaitGroup

	log.Println("Encrypting started")
	// To store the image data
	var imgData models.ImageData

	// Parse the multipart form data
	r.ParseMultipartForm(int64(10 << 20)) // limit size to 10 MB

	// Retrieve the file from form data
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "error retrieving the file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Get the file name
	imgData.FileName = handler.Filename

	// Decode the image
	img, format, err := image.Decode(file)
	if err != nil {
		http.Error(w, "Failed to decode the image", http.StatusBadRequest)
		return
	}
	imgData.Format = format

	// Buffer to store the bytes
	var buf bytes.Buffer

	// Encode the image to bytes
	switch format {
	case "jpeg":
		err = jpeg.Encode(&buf, img, nil)
	case "png":
		err = png.Encode(&buf, img)
	default:
		http.Error(w, "unsupported image format", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "Failed to encode image", http.StatusInternalServerError)
		return
	}

	// Encrypt the image data
	cipherData, err := imgData.EncryptAES(buf.Bytes())
	if err != nil {
		http.Error(w, "Image encryption failed", http.StatusInternalServerError)
		return
	}

	// Increment the WaitGroup counter for user ID retrieval
	wg.Add(1)

	// Get user ID asynchronously
	var userId uint
	go func() {
		defer wg.Done() // Notify when done
		id, ok := utils.GetUserId(r, models.UserIDKey)
		if ok {
			userId = id
		}
	}()

	// Wait for user ID retrieval to complete
	wg.Wait()

	// Check if user ID was retrieved
	if userId == 0 {
		http.Error(w, "An error occurred, please login again", http.StatusInternalServerError)
		return
	}

	// Add user ID to image data
	imgData.UserId = userId

	// Add image data to the database
	db, err := addData(&imgData)
	if err != nil {
		http.Error(w, "Failed to save image details", http.StatusInternalServerError)
		return
	}

	imgId := 0
	res := db.Table("image_data").Where("hash = ?", imgData.Hash).Select("id").Scan(&imgId)
	if res.RowsAffected == 0 {
		http.Error(w, "no file created", http.StatusInternalServerError)
		return
	}

	// Get the hash with user ID
	hash := utils.GetHash(uint(imgId), imgData.Hash)

	// Save image data with user ID to the database
	err = imgData.SaveHashToList(uint(userId), hash, db)
	if err != nil {
		http.Error(w, "Failed to add file to group", http.StatusInternalServerError)
		return
	}

	// Get user email
	userEmail, err := models.GetUserEmail(uint(userId), db)
	if err != nil {
		http.Error(w, "User does not exist", http.StatusBadRequest)
		return
	}

	// Prepare email details
	fileName := "Encrypted file name: " + strings.Split(imgData.FileName, ".")[0]

	// Send email asynchronously
	go func() {
		if err := auth.SendEmail(userEmail, fileName, cipherData, r); err != nil {
			log.Printf("Error sending email: %v", err)
		}
	}()

	// Write response
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	n, err := w.Write([]byte(hash))
	if err != nil {
		log.Println("writing to response failed:", err)
	} else if n <= 0 {
		log.Println("0 bytes written to response:", n)
	}
}

func DecodeImage(w http.ResponseWriter, r *http.Request) {
	var wg sync.WaitGroup
	var errChan = make(chan error, 1)
	var imgData models.ImageData

	key := r.URL.Query().Get("key")
	if len(key) < 64 {
		http.Error(w, "Invalid key length", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	fmt.Println("file received")
	if err != nil {
		http.Error(w, "error retriving the file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fmt.Println("Length of key: ", len(key))
	hash := key[:64]
	fmt.Println("Hash: ", hash)
	idStr := key[64:]
	fmt.Println("idStr: ", idStr)

	fmt.Println("Key: ", key)
	var id uint

	wg.Add(1)
	go func() {
		defer wg.Done()
		uid, err := utils.Convert(idStr)
		id = uid
		if err != nil {
			http.Error(w, "id convertion failed", http.StatusBadRequest)
		}
	}()
	wg.Wait()

	// Get the datas of the image using id or hash by utlizing type conversion in go
	wg.Add(1)
	go func() {
		defer wg.Done()
		imgData, err = getImageData(id, hash)
		if err != nil {
			errChan <- err
			return
		}
	}()
	wg.Wait()

	select {
	case err = <-errChan:
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	default:
	}

	fmt.Println("ID: ", id)
	fmt.Println("ImageData.Name: ", imgData.FileName, "ID: ", imgData.Id)

	// Read the file content into a []byte
	wg.Add(1)
	var cipherdata []byte
	go func() {
		defer wg.Done()
		cipherdata, err = io.ReadAll(file)
		if err != nil {
			errChan <- err
			return
		}
	}()
	wg.Wait()

	select {
	case err = <-errChan:
		http.Error(w, "please check the file you uploaded", http.StatusBadRequest)
		return
	default:
	}

	imgByte, err := imgData.DecryptAES(cipherdata)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// ---Uncomment to save locally---
	// err = generateImage(imgData, imgByte)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusBadRequest)
	// 	return
	// }

	// Check if the user wants to view or download the image
	action := r.URL.Query().Get("action")
	if action == "download" {
		// Set the header to force download
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(imgData.FileName))
	} else {
		// Set appropriate Content-Type based on the image format
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "image/"+imgData.Format)
		w.Write(imgByte)
	}
}

// getImageData by id and a hash and compare the hashs
func getImageData(id uint, hash string) (models.ImageData, error) {
	var imgDataByI models.ImageData
	var imgDataByH models.ImageData

	db, _ := config.Config()

	res := db.Table("image_data").Where("id = ?", id).Scan(&imgDataByI)
	if res.Error != nil {
		return models.ImageData{}, fmt.Errorf("user not found")
	}
	res = db.Table("image_data").Where("hash = ?", hash).Scan(&imgDataByH)
	if res.Error != nil {
		return models.ImageData{}, fmt.Errorf("user not found")
	}

	if imgDataByI.Hash == imgDataByH.Hash && imgDataByI.Hash == hash {
		return imgDataByI, nil
	}

	return models.ImageData{}, fmt.Errorf("no record found with id %v or hash %v", id, hash)
}

//    <----UNCOMMENT TO SAVE LOCALLY----->

// func decode(data []byte) (image.Image, error) {
// 	img, _, err := image.Decode(bytes.NewBuffer(data))
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to decode the image: %w", err)
// 	}
// 	return img, err
// }

// func generateImage(imgData models.ImageData, imgByte []byte) error {
// 	switch imgData.Format {
// 	case "jpeg":
// 		image, err := decode(imgByte)
// 		if err != nil {
// 			return err
// 		}
// 		err = createImage(imgData, image)
// 		if err != nil {
// 			return err
// 		}

// 	case "png":
// 		image, err := decode(imgByte)
// 		if err != nil {
// 			return err
// 		}
// 		err = createImage(imgData, image)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

// func createImage(data models.ImageData, image image.Image) error {
// 	// Get the user's home directory dynamically
// 	homeDir, err := os.UserHomeDir()
// 	if err != nil {
// 		return fmt.Errorf("unable to get home directory: %v", err)
// 	}

// 	// Construct the full path
// 	savePath := filepath.Join(homeDir, "Downloads", data.FileName)
// 	file, err := os.OpenFile(
// 		savePath, // set file path and name accordingly
// 		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
// 		0644,
// 	)
// 	if err != nil {
// 		fmt.Println("error")
// 		return err
// 	}

// 	defer file.Close()

// 	switch data.Format {
// 	case "jpeg":
// 		err := jpeg.Encode(file, image, nil)
// 		if err != nil {
// 			return err
// 		}

// 	case "png":
// 		err := png.Encode(file, image)
// 		if err != nil {
// 			return err
// 		}

// 	default:
// 		return fmt.Errorf("unsupported image format: %s", data.Format)
// 	}

// 	return nil
// }
