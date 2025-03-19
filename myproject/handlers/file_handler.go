package handlers

import (
    "html/template"
    "io"
    "myproject/models"
    "myproject/utils"
    "net/http"
    "os"
    "path/filepath"
    "strconv"
)

func UploadFile(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        file, handler, err := r.FormFile("file")
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        defer file.Close()

        uploadDir := "uploads"
        err = os.MkdirAll(uploadDir, os.ModePerm)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        filepath := filepath.Join(uploadDir, handler.Filename)
        dst, err := os.Create(filepath)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        defer dst.Close()

        _, err = io.Copy(dst, file)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        _, err = utils.DB.Exec("INSERT INTO files (filename, filepath) VALUES (?, ?)", handler.Filename, filepath)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
        return
    }

    files, err := getAllFiles()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    tmpl, err := template.ParseFiles("templates/upload_file.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    data := struct {
        Files []models.File
    }{
        Files: files,
    }

    tmpl.Execute(w, data)
}

func DeleteFile(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        fileID, err := strconv.Atoi(r.FormValue("file_id"))
        if err != nil {
            http.Error(w, "Invalid file ID", http.StatusBadRequest)
            return
        }

        file, err := getFileByID(fileID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        err = os.Remove(file.Filepath)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        _, err = utils.DB.Exec("DELETE FROM files WHERE id = ?", fileID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
        return
    }
}

func getAllFiles() ([]models.File, error) {
    rows, err := utils.DB.Query("SELECT id, filename, filepath FROM files")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var files []models.File
    for rows.Next() {
        var file models.File
        err := rows.Scan(&file.ID, &file.Filename, &file.Filepath)
        if err != nil {
            return nil, err
        }
        files = append(files, file)
    }

    return files, nil
}

func getFileByID(fileID int) (models.File, error) {
    var file models.File
    err := utils.DB.QueryRow("SELECT id, filename, filepath FROM files WHERE id = ?", fileID).Scan(&file.ID, &file.Filename, &file.Filepath)
    if err != nil {
        return file, err
    }
    return file, nil
}
