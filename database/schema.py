class Schema:
    @staticmethod
    def Client():
        return """
       CREATE TABLE IF NOT EXISTS Client (
           user_name TEXT PRIMARY KEY,
           IP TEXT NOT NULL,
           status BOOLEAN NOT NULL,
           time_stamp DATE NOT NULL
       );
       """

    @staticmethod
    def Image():
        return """
       CREATE TABLE IF NOT EXISTS Image (
           image_id INTEGER PRIMARY KEY NOT NULL,
           user_name TEXT NOT NULL,
           image BLOB NOT NULL,
           FOREIGN KEY(user_name) REFERENCES Client(user_name)
       );
       """
