class Schema:
    @staticmethod
    def Client():
        return """
       CREATE TABLE IF NOT EXISTS Client (
           user_name TEXT PRIMARY KEY,
           ip_addr TEXT NOT NULL,
           status INTEGER NOT NULL,
           time_stamp DATE NOT NULL
       );
       """

    @staticmethod
    def Image():
        return """
       CREATE TABLE IF NOT EXISTS Image (
           image_name TEXT  NOT NULL,
           image_bytes BLOB NOT NULL,
           user_name TEXT NOT NULL,
           PRIMARY KEY (image_name, user_name),
           FOREIGN KEY(user_name) REFERENCES Client(user_name)
       );
       """
    
    @staticmethod
    def ImageAccess():
        return '''
       CREATE TABLE IF NOT EXISTS ImageAccess (
            status INTEGER NOT NULL,
            owner TEXT NOT NULL,
            viewer TEXT NOT NULL,
            image_name TEXT NOT NULL,
            prop_views INTEGER NOT NULL,
            accep_views INTEGER NOT NULL,
            PRIMARY KEY (owner, image_name, viewer),
            FOREIGN KEY(owner) REFERENCES Client(user_name),
            FOREIGN KEY(viewer) REFERENCES Client(user_name),
            FOREIGN KEY(image_name) REFERENCES Image(image_name)
        );
        '''
